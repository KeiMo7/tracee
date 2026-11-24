package ipreputation

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/common/logger"
)

const (
	// DefaultMaxEntries bounds the store unless configured otherwise.
	DefaultMaxEntries = 1_000_000
	// DefaultSweepInterval is how often expired entries are reclaimed.
	DefaultSweepInterval = 30 * time.Second
	// EvictionPolicyLRU is the deterministic capacity policy: the least
	// recently written entry is evicted first. Ties are broken by source name
	// and then by network, so a given input always evicts the same entries.
	EvictionPolicyLRU = "least_recently_written"

	storeName = "ip_reputation"
)

// Config configures an IPReputationStore.
type Config struct {
	// ConflictPolicy decides which source wins when several sources publish the
	// same prefix. Defaults to LastWriteWins.
	ConflictPolicy ConflictResolutionPolicy

	// SourcePriority ranks sources for PriorityBased conflict resolution.
	SourcePriority map[string]int

	// MaxEntries is the hard capacity. Zero uses DefaultMaxEntries; a negative
	// value disables the cap (useful for tests).
	MaxEntries int

	// DefaultTTL is applied to entries written without a TTL or expiry.
	// Zero means entries never expire.
	DefaultTTL time.Duration

	// SweepInterval is how often the background reclaimer runs once the store is
	// initialized. Zero uses DefaultSweepInterval; negative disables the
	// background sweeper (SweepExpired can still be called explicitly).
	SweepInterval time.Duration

	// Clock overrides time.Now. It exists for deterministic tests.
	Clock func() time.Time
}

// DefaultConfig returns a Config with production defaults.
func DefaultConfig() Config {
	return Config{
		ConflictPolicy: LastWriteWins,
		MaxEntries:     DefaultMaxEntries,
		SweepInterval:  DefaultSweepInterval,
	}
}

func (c Config) withDefaults() Config {
	if c.ConflictPolicy < LastWriteWins || c.ConflictPolicy > PriorityBased {
		c.ConflictPolicy = LastWriteWins
	}
	if c.MaxEntries == 0 {
		c.MaxEntries = DefaultMaxEntries
	}
	if c.SweepInterval == 0 {
		c.SweepInterval = DefaultSweepInterval
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	return c
}

// Stats is a point-in-time snapshot of store counters.
type Stats struct {
	Entries          int    // entries currently held in memory (expired ones may be pending reclamation)
	LiveEntries      int    // entries that are not expired as of now
	Prefixes         int    // distinct networks (exact addresses count as /32 or /128)
	Sources          int    // sources with at least one entry
	Capacity         int    // configured maximum, negative when unlimited
	ExpiredReclaimed uint64 // entries removed by the expiry reclaimer
	Evicted          uint64 // entries removed by the capacity policy
	EvictionPolicy   string // name of the capacity policy in effect
	Queries          uint64 // address lookups performed
	Hits             uint64 // address lookups that matched
	Misses           uint64 // address lookups that did not match
	LastAccess       time.Time
	LastEviction     time.Time
}

// IPReputationStore provides IP reputation lookup with conflict resolution.
//
// Reads are lock-free: writers publish an immutable snapshot and queries load
// it with a single atomic read, so a write can never block a query and a query
// can never observe a half-applied write or a partially reclaimed entry.
type IPReputationStore interface {
	datastores.WritableStore

	// Type-safe write methods for internal Go usage.
	// The ip argument accepts a single address or a network in CIDR notation.
	WriteReputation(source string, ip string, rep *IPReputation) error
	WriteReputationBatch(source string, data map[string]*IPReputation) error

	// Query operations.
	//
	// GetReputation and the legacy helpers below keep their historical
	// signatures. They return (nil, false) for malformed input; use Lookup,
	// LookupBatch or Match when the caller needs invalid input reported.

	// GetReputation returns the longest-prefix match for an address, or the
	// exact entry when ip is a network in CIDR notation.
	GetReputation(ip string) (*IPReputation, bool)
	IsDenied(ip string) bool
	IsAllowed(ip string) bool
	CheckIPs(ips []string) map[string]*IPReputation

	// Lookup returns the longest-prefix match for ip. It returns false when
	// nothing matches and an error when ip is not a valid address or network.
	Lookup(ip string) (*IPReputation, bool, error)

	// LookupBatch resolves every entry against one immutable snapshot, so the
	// results are mutually consistent even while writers and the reclaimer run.
	// It fails without returning partial results if any input is invalid.
	LookupBatch(ips []string) (map[string]*IPReputation, error)

	// Match and MatchBatch are the detector-facing read API. They return
	// datastores.ErrNotFound when nothing matches and
	// datastores.ErrInvalidArgument for malformed input.
	Match(ip string) (*datastores.IPReputationMatch, error)
	MatchBatch(ips []string) (map[string]*datastores.IPReputationMatch, error)

	// Stats returns the operational counters.
	Stats() Stats

	// SweepExpired reclaims entries whose expiry is at or before now and
	// returns how many were removed. It is safe to call concurrently with
	// queries and writes.
	SweepExpired(now time.Time) int

	// StartSweeper starts the background reclaimer (idempotent).
	StartSweeper()
	// Close stops the background reclaimer.
	Close() error
}

// entry is immutable once published in a snapshot.
type entry struct {
	source string
	prefix netip.Prefix
	exact  bool // written as a bare address rather than a network
	rep    *IPReputation
	seq    uint64 // global write order, used for deterministic eviction
}

// node holds all source entries for one distinct prefix. It is immutable.
type node struct {
	prefix  netip.Prefix
	entries map[string]*entry // source -> entry
}

const maxPrefixBits = 128

// snapshot is an immutable view of the store. Maps are never mutated after
// publication; writers copy the outer maps and only the nodes they touch.
type snapshot struct {
	nets     map[netip.Prefix]*node
	bySource map[string]map[netip.Prefix]*entry
	count    int
	// lenCount[fam][bits] is the number of nodes at that prefix length, used to
	// skip prefix lengths that cannot match. Index 0 is IPv4, 1 is IPv6.
	lenCount [2][maxPrefixBits + 1]int
}

func newSnapshot() *snapshot {
	return &snapshot{
		nets:     make(map[netip.Prefix]*node),
		bySource: make(map[string]map[netip.Prefix]*entry),
	}
}

func (s *snapshot) cloneTop() *snapshot {
	n := &snapshot{
		nets:     make(map[netip.Prefix]*node, len(s.nets)),
		bySource: make(map[string]map[netip.Prefix]*entry, len(s.bySource)),
		count:    s.count,
		lenCount: s.lenCount,
	}
	for p, node := range s.nets {
		n.nets[p] = node
	}
	for src, m := range s.bySource {
		n.bySource[src] = m
	}
	return n
}

func copyEntries(m map[string]*entry) map[string]*entry {
	out := make(map[string]*entry, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

func copySourceMap(m map[netip.Prefix]*entry) map[netip.Prefix]*entry {
	out := make(map[netip.Prefix]*entry, len(m)+1)
	for k, v := range m {
		out[k] = v
	}
	return out
}

func prefixFamily(p netip.Prefix) int {
	if p.Addr().Is4() {
		return 0
	}
	return 1
}

// put inserts or replaces an entry in this snapshot.
func (n *snapshot) put(e *entry) {
	fam := prefixFamily(e.prefix)
	bits := e.prefix.Bits()

	old := n.nets[e.prefix]
	if old == nil {
		n.nets[e.prefix] = &node{
			prefix:  e.prefix,
			entries: map[string]*entry{e.source: e},
		}
		n.lenCount[fam][bits]++
		n.count++
	} else {
		entries := copyEntries(old.entries)
		if _, exists := entries[e.source]; !exists {
			n.count++
		}
		entries[e.source] = e
		n.nets[e.prefix] = &node{prefix: e.prefix, entries: entries}
	}

	bySource := copySourceMap(n.bySource[e.source])
	bySource[e.prefix] = e
	n.bySource[e.source] = bySource
}

// remove deletes one (source, prefix) entry. It reports whether it existed.
func (n *snapshot) remove(prefix netip.Prefix, source string) bool {
	old := n.nets[prefix]
	if old == nil {
		return false
	}
	if _, exists := old.entries[source]; !exists {
		return false
	}

	entries := copyEntries(old.entries)
	delete(entries, source)
	if len(entries) == 0 {
		delete(n.nets, prefix)
		n.lenCount[prefixFamily(prefix)][prefix.Bits()]--
	} else {
		n.nets[prefix] = &node{prefix: prefix, entries: entries}
	}

	bySource := copySourceMap(n.bySource[source])
	delete(bySource, prefix)
	if len(bySource) == 0 {
		delete(n.bySource, source)
	} else {
		n.bySource[source] = bySource
	}

	n.count--
	return true
}

// allEntries returns every entry; used for capacity enforcement and stats.
func (n *snapshot) allEntries() []*entry {
	out := make([]*entry, 0, n.count)
	for _, m := range n.bySource {
		for _, e := range m {
			out = append(out, e)
		}
	}
	return out
}

// Store implements IPReputationStore.
type Store struct {
	cfg Config
	now func() time.Time

	writeMu sync.Mutex
	snap    atomic.Pointer[snapshot]

	seq atomic.Uint64

	queries     atomic.Uint64
	hits        atomic.Uint64
	misses      atomic.Uint64
	queryErrors atomic.Uint64
	lastAccess  atomic.Int64

	expiredReclaimed atomic.Uint64
	evicted          atomic.Uint64
	lastEviction     atomic.Int64

	// probes counts prefix lookups; it lets tests prove that a query costs
	// O(address bits) rather than O(entries).
	probes atomic.Uint64

	janitorMu    sync.Mutex
	janitorStop  chan struct{}
	janitorWG    sync.WaitGroup
	janitorAlive bool
}

var _ IPReputationStore = (*Store)(nil)
var _ datastores.IPReputationStore = (*Store)(nil)

// NewIPReputationStore preserves the historical constructor.
func NewIPReputationStore(policy ConflictResolutionPolicy, sourcePriority map[string]int) IPReputationStore {
	return NewIPReputationStoreWithConfig(Config{
		ConflictPolicy: policy,
		SourcePriority: sourcePriority,
	})
}

// NewIPReputationStoreWithConfig creates a Store from cfg, applying defaults
// for zero-valued fields. The concrete type is returned so internal callers can
// use Stats, SweepExpired and the background sweeper.
func NewIPReputationStoreWithConfig(cfg Config) *Store {
	cfg = cfg.withDefaults()
	if cfg.SourcePriority == nil {
		cfg.SourcePriority = map[string]int{}
	} else {
		// Copy so later caller mutations cannot change conflict decisions.
		prio := make(map[string]int, len(cfg.SourcePriority))
		for k, v := range cfg.SourcePriority {
			prio[k] = v
		}
		cfg.SourcePriority = prio
	}

	s := &Store{cfg: cfg, now: cfg.Clock}
	s.snap.Store(newSnapshot())
	return s
}

// DataStore interface implementation.

func (s *Store) Name() string { return storeName }

func (s *Store) GetHealth() *datastores.HealthInfo {
	return &datastores.HealthInfo{
		Status:    datastores.HealthHealthy,
		Message:   "",
		LastCheck: s.now(),
	}
}

func (s *Store) GetMetrics() *datastores.DataStoreMetrics {
	snap := s.snap.Load()
	return &datastores.DataStoreMetrics{
		ItemCount:    int64(snap.count),
		SuccessCount: s.hits.Load(),
		ErrorCount:   s.queryErrors.Load(),
		CacheHits:    s.hits.Load(),
		CacheMisses:  s.misses.Load(),
		LastAccess:   time.Unix(0, s.lastAccess.Load()),
		Extra: map[string]int64{
			"entries":            int64(snap.count),
			"prefixes":           int64(len(snap.nets)),
			"sources":            int64(len(snap.bySource)),
			"capacity":           int64(s.cfg.MaxEntries),
			"queries":            int64(s.queries.Load()),
			"expired_reclaimed":  int64(s.expiredReclaimed.Load()),
			"evicted":            int64(s.evicted.Load()),
			"last_eviction_unix": s.lastEviction.Load() / int64(time.Second),
		},
	}
}

// Stats returns operational counters.
func (s *Store) Stats() Stats {
	snap := s.snap.Load()
	now := s.now()
	live := 0
	for _, e := range snap.allEntries() {
		if !expired(e, now) {
			live++
		}
	}

	var lastEviction time.Time
	if ns := s.lastEviction.Load(); ns != 0 {
		lastEviction = time.Unix(0, ns)
	}

	return Stats{
		Entries:          snap.count,
		LiveEntries:      live,
		Prefixes:         len(snap.nets),
		Sources:          len(snap.bySource),
		Capacity:         s.cfg.MaxEntries,
		ExpiredReclaimed: s.expiredReclaimed.Load(),
		Evicted:          s.evicted.Load(),
		EvictionPolicy:   EvictionPolicyLRU,
		Queries:          s.queries.Load(),
		Hits:             s.hits.Load(),
		Misses:           s.misses.Load(),
		LastAccess:       time.Unix(0, s.lastAccess.Load()),
		LastEviction:     lastEviction,
	}
}

// Lifecycle.

// Initialize starts the background expiry reclaimer.
func (s *Store) Initialize(context.Context) error {
	s.StartSweeper()
	return nil
}

// Shutdown stops the background expiry reclaimer.
func (s *Store) Shutdown(context.Context) error { return s.Close() }

// StartSweeper starts the background reclaimer. It is idempotent.
func (s *Store) StartSweeper() {
	if s.cfg.SweepInterval < 0 {
		return
	}

	s.janitorMu.Lock()
	defer s.janitorMu.Unlock()
	if s.janitorAlive {
		return
	}
	s.janitorStop = make(chan struct{})
	s.janitorAlive = true

	stop := s.janitorStop
	interval := s.cfg.SweepInterval
	s.janitorWG.Add(1)
	go func() {
		defer s.janitorWG.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				s.SweepExpired(s.now())
			}
		}
	}()
}

// Close stops the background reclaimer. It is safe to call more than once.
func (s *Store) Close() error {
	s.janitorMu.Lock()
	if !s.janitorAlive {
		s.janitorMu.Unlock()
		return nil
	}
	close(s.janitorStop)
	s.janitorAlive = false
	s.janitorMu.Unlock()

	s.janitorWG.Wait()
	return nil
}

// SweepExpired reclaims expired entries and publishes the reduced snapshot
// atomically, so concurrent queries see either the old or the new snapshot.
func (s *Store) SweepExpired(now time.Time) int {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	old := s.snap.Load()
	keys := make([]netip.Prefix, 0)
	sources := make([]string, 0)

	for prefix, node := range old.nets {
		for source, e := range node.entries {
			if expired(e, now) {
				keys = append(keys, prefix)
				sources = append(sources, source)
			}
		}
	}
	if len(keys) == 0 {
		return 0
	}

	ns := old.cloneTop()
	removed := 0
	for i := range keys {
		if ns.remove(keys[i], sources[i]) {
			removed++
		}
	}

	s.snap.Store(ns)
	if removed > 0 {
		s.expiredReclaimed.Add(uint64(removed))
	}
	return removed
}

// WritableStore interface implementation.

// validateReputation validates reputation data.
func validateReputation(rep *IPReputation) error {
	if rep == nil {
		return fmt.Errorf("nil reputation")
	}
	if rep.Severity < 1 || rep.Severity > 10 {
		return fmt.Errorf("severity must be 1-10, got %d", rep.Severity)
	}
	// Validate status enum range (protobuf enum values)
	if rep.Status < ReputationUnknown || rep.Status > ReputationSuspicious {
		return fmt.Errorf("invalid reputation status: %d", rep.Status)
	}
	if rep.TTL < 0 {
		return fmt.Errorf("ttl must not be negative, got %s", rep.TTL)
	}
	return nil
}

// Write writes a single IP reputation entry from protobuf format.
func (s *Store) Write(source string, entry *datastores.DataEntry) error {
	rep, err := unpackEntry(source, entry)
	if err != nil {
		return err
	}
	return s.WriteReputation(source, rep.IP, rep)
}

// WriteBatch writes multiple IP reputation entries from protobuf format.
// All entries are validated before anything is written.
func (s *Store) WriteBatch(source string, entries []*datastores.DataEntry) error {
	reps := make([]keyedRep, 0, len(entries))
	for i, entry := range entries {
		rep, err := unpackEntry(source, entry)
		if err != nil {
			return fmt.Errorf("entry %d: %w", i, err)
		}
		reps = append(reps, keyedRep{key: rep.IP, rep: rep})
	}
	return s.writeReputations(source, reps)
}

// unpackEntry converts one protobuf DataEntry into an internal reputation.
func unpackEntry(source string, entry *datastores.DataEntry) (*IPReputation, error) {
	if entry == nil {
		return nil, fmt.Errorf("nil data entry")
	}

	var keyMsg datastores.IPAddressKey
	if err := entry.Key.UnmarshalTo(&keyMsg); err != nil {
		return nil, fmt.Errorf("invalid key type (expected IPAddressKey): %w", err)
	}

	var repMsg datastores.IPReputation
	if err := entry.Data.UnmarshalTo(&repMsg); err != nil {
		return nil, fmt.Errorf("invalid data type (expected IPReputation): %w", err)
	}

	// Validate status enum from protobuf
	if repMsg.Status < 0 || repMsg.Status > 3 {
		return nil, fmt.Errorf("invalid reputation status: %d", repMsg.Status)
	}

	rep := &IPReputation{
		IP:          keyMsg.Ip,
		Status:      ReputationStatus(repMsg.Status),
		Source:      source,
		Severity:    int(repMsg.Severity),
		Tags:        repMsg.Tags,
		LastUpdated: time.Time{},
		Metadata:    repMsg.Metadata,
	}
	if ts := repMsg.GetLastUpdated(); ts != nil {
		rep.LastUpdated = ts.AsTime()
	}
	if d := repMsg.GetTtl(); d != nil {
		rep.TTL = d.AsDuration()
	}
	if ts := repMsg.GetExpiresAt(); ts != nil {
		rep.ExpiresAt = ts.AsTime()
	}

	return rep, nil
}

// Delete removes a specific key entry from a source.
// Returns nil if the key doesn't exist (idempotent).
func (s *Store) Delete(source string, key *anypb.Any) error {
	if key == nil {
		return fmt.Errorf("nil key")
	}
	var keyMsg datastores.IPAddressKey
	if err := key.UnmarshalTo(&keyMsg); err != nil {
		return fmt.Errorf("invalid key type (expected IPAddressKey): %w", err)
	}

	parsed, err := normalizeKey(keyMsg.Ip)
	if err != nil {
		return fmt.Errorf("invalid key %q: %w", keyMsg.Ip, err)
	}
	prefix := parsed.indexPrefix()

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	old := s.snap.Load()
	if old.nets[prefix] == nil {
		return nil
	}
	ns := old.cloneTop()
	ns.remove(prefix, source)
	s.snap.Store(ns)
	return nil
}

// Clear removes all data from a specific source. Other sources keep their
// entries, including entries for the same prefix.
func (s *Store) Clear(source string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	old := s.snap.Load()
	entries := old.bySource[source]
	if len(entries) == 0 {
		return nil
	}

	ns := old.cloneTop()
	for prefix := range entries {
		ns.remove(prefix, source)
	}
	s.snap.Store(ns)
	return nil
}

// ListSources returns all source identifiers that have data, sorted.
func (s *Store) ListSources() ([]string, error) {
	snap := s.snap.Load()
	sources := make([]string, 0, len(snap.bySource))
	for source := range snap.bySource {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	return sources, nil
}

// Type-safe methods for internal Go usage.

// WriteReputation writes a single entry using native Go types. ip may be an
// address or a network in CIDR notation.
func (s *Store) WriteReputation(source string, ip string, rep *IPReputation) error {
	if err := validateReputation(rep); err != nil {
		return err
	}
	return s.writeReputations(source, []keyedRep{{key: ip, rep: rep}})
}

// keyedRep pairs the address a caller wrote with the reputation payload.
type keyedRep struct {
	key string
	rep *IPReputation
}

// WriteReputationBatch writes multiple entries using native Go types.
// The map key is authoritative for the address; a non-empty rep.IP must agree
// with it. All entries are validated before anything is written.
func (s *Store) WriteReputationBatch(source string, data map[string]*IPReputation) error {
	// Sort keys so write order (and therefore eviction order on ties) is stable.
	keys := make([]string, 0, len(data))
	for ip := range data {
		keys = append(keys, ip)
	}
	sort.Strings(keys)

	reps := make([]keyedRep, 0, len(keys))
	for _, ip := range keys {
		rep := data[ip]
		if rep == nil {
			return fmt.Errorf("nil reputation for %q", ip)
		}
		if rep.IP != "" && rep.IP != ip {
			return fmt.Errorf("key %q does not match entry address %q", ip, rep.IP)
		}
		reps = append(reps, keyedRep{key: ip, rep: rep})
	}
	return s.writeReputations(source, reps)
}

// writeReputations validates and applies a batch atomically.
func (s *Store) writeReputations(source string, reps []keyedRep) error {
	now := s.now()

	prepared := make([]*entry, 0, len(reps))
	for i, kr := range reps {
		parsed, err := normalizeKey(kr.key)
		if err != nil {
			if len(reps) == 1 {
				return fmt.Errorf("invalid IP %q: %w", kr.key, err)
			}
			return fmt.Errorf("entry %d (%q): %w", i, kr.key, err)
		}
		e, err := s.prepareEntry(source, parsed, kr.rep, now)
		if err != nil {
			if len(reps) == 1 {
				return fmt.Errorf("entry %q: %w", kr.key, err)
			}
			return fmt.Errorf("entry %d (%q): %w", i, kr.key, err)
		}
		prepared = append(prepared, e)
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	old := s.snap.Load()
	ns := old.cloneTop()
	for _, e := range prepared {
		ns.put(e)
	}

	if evicted := s.enforceCapacity(ns, now); evicted > 0 {
		total := s.evicted.Add(uint64(evicted))
		s.lastEviction.Store(now.UnixNano())
		// Log the first eviction and then at most once per 10k, so a sustained
		// overload is reported without flooding the log on every write.
		if total == uint64(evicted) || total%10000 < uint64(evicted) {
			logger.Warnw("IP reputation store capacity reached, entries evicted",
				"capacity", s.cfg.MaxEntries,
				"evicted_now", evicted,
				"evicted_total", total,
				"policy", EvictionPolicyLRU,
				"store", storeName,
			)
		}
	}

	s.snap.Store(ns)
	s.lastAccess.Store(now.UnixNano())
	return nil
}

// prepareEntry validates and normalizes one entry for publication.
func (s *Store) prepareEntry(source string, key parsedKey, rep *IPReputation, now time.Time) (*entry, error) {
	if err := validateReputation(rep); err != nil {
		return nil, err
	}

	stored := rep.clone()
	stored.Source = source
	stored.IP = key.String()
	stored.MatchedPrefix = ""

	switch {
	case !stored.ExpiresAt.IsZero():
		stored.ExpiresAt = stored.ExpiresAt.UTC()
	case stored.TTL > 0:
		stored.ExpiresAt = now.Add(stored.TTL)
	case s.cfg.DefaultTTL > 0:
		stored.ExpiresAt = now.Add(s.cfg.DefaultTTL)
	}
	// ExpiresAt is authoritative from here on; TTL was only the input form.
	stored.TTL = 0

	prefix := key.indexPrefix()
	return &entry{
		source: source,
		prefix: prefix,
		exact:  key.kind == keyAddr,
		rep:    stored,
		seq:    s.seq.Add(1),
	}, nil
}

// enforceCapacity evicts entries until the snapshot is within the configured
// capacity. Expired entries go first (they would never match again), then the
// least recently written entries. Ties are broken by source and prefix, so the
// same input always evicts the same entries. It returns the number evicted.
//
// Eviction drains to a low watermark rather than stopping exactly at the limit,
// so the O(n log n) sort is paid once per batch of writes instead of on every
// write while the store is full.
func (s *Store) enforceCapacity(ns *snapshot, now time.Time) int {
	if s.cfg.MaxEntries < 0 || ns.count <= s.cfg.MaxEntries {
		return 0
	}

	target := s.cfg.MaxEntries - s.cfg.MaxEntries/10 // 90% low watermark
	if target < 0 {
		target = 0
	}

	victims := ns.count - target
	all := ns.allEntries()
	sort.Slice(all, func(i, j int) bool {
		ei, ej := expired(all[i], now), expired(all[j], now)
		if ei != ej {
			return ei // expired entries sort first
		}
		if all[i].seq != all[j].seq {
			return all[i].seq < all[j].seq
		}
		if all[i].source != all[j].source {
			return all[i].source < all[j].source
		}
		return all[i].prefix.String() < all[j].prefix.String()
	})
	if victims > len(all) {
		victims = len(all)
	}

	removed := 0
	for i := 0; i < victims; i++ {
		if ns.remove(all[i].prefix, all[i].source) {
			removed++
		}
	}
	return removed
}

// Queries.

// GetReputation retrieves the longest-prefix match for an address, or the exact
// network entry when ip is in CIDR notation. Malformed input returns false.
func (s *Store) GetReputation(ip string) (*IPReputation, bool) {
	rep, found, err := s.Lookup(ip)
	if err != nil || !found {
		return nil, false
	}
	return rep, true
}

// Lookup returns the longest-prefix match for ip.
func (s *Store) Lookup(ip string) (*IPReputation, bool, error) {
	s.queries.Add(1)
	parsed, err := normalizeKey(ip)
	if err != nil {
		s.queryErrors.Add(1)
		return nil, false, err
	}

	snap := s.snap.Load()
	now := s.now()
	e := s.match(snap, parsed, now)

	if e == nil {
		s.misses.Add(1)
		return nil, false, nil
	}
	s.hits.Add(1)
	s.lastAccess.Store(now.UnixNano())
	return resultFrom(e), true, nil
}

// match resolves a normalized key against a snapshot without touching metrics.
func (s *Store) match(snap *snapshot, key parsedKey, now time.Time) *entry {
	if key.kind == keyPrefix {
		return s.resolveNode(snap.nets[key.prefix], now)
	}
	return s.longestMatch(snap, key.addr, now)
}

func (s *Store) longestMatch(snap *snapshot, addr netip.Addr, now time.Time) *entry {
	fam := 0
	if !addr.Is4() {
		fam = 1
	}

	for bits := addr.BitLen(); bits >= 0; bits-- {
		if snap.lenCount[fam][bits] == 0 {
			continue
		}
		s.probes.Add(1)
		prefix := netip.PrefixFrom(addr, bits).Masked()
		if e := s.resolveNode(snap.nets[prefix], now); e != nil {
			return e
		}
	}
	return nil
}

// resolveNode applies the conflict policy across the live sources at one node.
func (s *Store) resolveNode(n *node, now time.Time) *entry {
	if n == nil {
		return nil
	}
	var best *entry
	for _, e := range n.entries {
		if expired(e, now) {
			continue
		}
		if best == nil || s.prefer(e, best) {
			best = e
		}
	}
	return best
}

// prefer reports whether a should win over b. The policy criteria come first;
// remaining ties fall back to write order and then source name, so the winner
// never depends on map iteration order.
func (s *Store) prefer(a, b *entry) bool {
	severity := func() (bool, bool) {
		if a.rep.Severity == b.rep.Severity {
			return false, false
		}
		return a.rep.Severity > b.rep.Severity, true
	}
	priority := func() (bool, bool) {
		pa, pb := s.cfg.SourcePriority[a.source], s.cfg.SourcePriority[b.source]
		if pa == pb {
			return false, false
		}
		return pa > pb, true
	}
	recency := func() (bool, bool) {
		at, bt := a.rep.LastUpdated, b.rep.LastUpdated
		if at.Equal(bt) {
			return false, false
		}
		return at.After(bt), true
	}
	stable := func() bool {
		if a.seq != b.seq {
			return a.seq > b.seq
		}
		return a.source < b.source
	}

	var ordered []func() (bool, bool)
	switch s.cfg.ConflictPolicy {
	case MaxSeverity:
		ordered = []func() (bool, bool){severity, priority, recency}
	case PriorityBased:
		ordered = []func() (bool, bool){priority, severity, recency}
	default: // LastWriteWins
		ordered = []func() (bool, bool){recency}
	}

	for _, criterion := range ordered {
		if wins, decided := criterion(); decided {
			return wins
		}
	}
	return stable()
}

// resultFrom clones the stored entry and annotates network matches.
func resultFrom(e *entry) *IPReputation {
	rep := e.rep.clone()
	if e.exact {
		rep.MatchedPrefix = ""
	} else {
		rep.MatchedPrefix = e.prefix.String()
	}
	return rep
}

// LookupBatch resolves all inputs against a single snapshot.
func (s *Store) LookupBatch(ips []string) (map[string]*IPReputation, error) {
	parsed := make([]parsedKey, len(ips))
	s.queries.Add(uint64(len(ips)))
	for i, ip := range ips {
		key, err := normalizeKey(ip)
		if err != nil {
			s.queryErrors.Add(1)
			return nil, fmt.Errorf("entry %d (%q): %w", i, ip, err)
		}
		parsed[i] = key
	}

	snap := s.snap.Load()
	now := s.now()

	results := make(map[string]*IPReputation, len(ips))
	seen := make(map[parsedKey]*entry, len(ips))
	lookups := uint64(0)
	hits := uint64(0)

	for i, key := range parsed {
		e, ok := seen[key]
		if !ok {
			e = s.match(snap, key, now)
			seen[key] = e
			lookups++
			if e != nil {
				hits++
			}
		}
		if e != nil {
			results[ips[i]] = resultFrom(e)
		}
	}

	if lookups > 0 {
		s.hits.Add(hits)
		s.misses.Add(lookups - hits)
	}
	if hits > 0 {
		s.lastAccess.Store(now.UnixNano())
	}
	return results, nil
}

// CheckIPs preserves the historical batch helper: only matches are returned and
// malformed inputs are ignored.
func (s *Store) CheckIPs(ips []string) map[string]*IPReputation {
	results := make(map[string]*IPReputation, len(ips))
	for _, ip := range ips {
		if rep, found := s.GetReputation(ip); found {
			results[ip] = rep
		}
	}
	return results
}

// IsDenied checks if an address has a deny/block reputation.
func (s *Store) IsDenied(ip string) bool {
	rep, found := s.GetReputation(ip)
	return found && rep.Status == ReputationDeny
}

// IsAllowed checks if an address has an allow/trusted reputation.
func (s *Store) IsAllowed(ip string) bool {
	rep, found := s.GetReputation(ip)
	return found && rep.Status == ReputationAllow
}

// Match implements the detector-facing read API.
func (s *Store) Match(ip string) (*datastores.IPReputationMatch, error) {
	rep, found, err := s.Lookup(ip)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", datastores.ErrInvalidArgument, err)
	}
	if !found {
		return nil, datastores.ErrNotFound
	}
	return toMatch(ip, rep), nil
}

// MatchBatch implements the detector-facing batch read API. Missing addresses
// are omitted from the result; malformed input fails the whole call.
func (s *Store) MatchBatch(ips []string) (map[string]*datastores.IPReputationMatch, error) {
	reps, err := s.LookupBatch(ips)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", datastores.ErrInvalidArgument, err)
	}
	matches := make(map[string]*datastores.IPReputationMatch, len(reps))
	for ip, rep := range reps {
		matches[ip] = toMatch(ip, rep)
	}
	return matches, nil
}

func toMatch(query string, rep *IPReputation) *datastores.IPReputationMatch {
	return &datastores.IPReputationMatch{
		Query:       query,
		IP:          rep.IP,
		Prefix:      rep.MatchedPrefix,
		Status:      rep.Status.String(),
		Severity:    rep.Severity,
		Tags:        append([]string(nil), rep.Tags...),
		Source:      rep.Source,
		LastUpdated: rep.LastUpdated,
		ExpiresAt:   rep.ExpiresAt,
		Metadata:    copyStringMap(rep.Metadata),
	}
}

func copyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func expired(e *entry, now time.Time) bool {
	return !e.rep.ExpiresAt.IsZero() && !now.Before(e.rep.ExpiresAt)
}
