package ipreputation

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// testClock is a manually advanced clock for deterministic expiry tests.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock {
	return &testClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestStore(t *testing.T, cfg Config) *Store {
	t.Helper()
	if cfg.Clock == nil {
		cfg.Clock = newTestClock().Now
	}
	s := NewIPReputationStoreWithConfig(cfg)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func deny(severity int) *IPReputation {
	return &IPReputation{Status: ReputationDeny, Severity: severity}
}

func TestLongestPrefixMatch_IPv4(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	s := NewIPReputationStoreWithConfig(Config{MaxEntries: -1, SweepInterval: -1, Clock: clock.Now})
	t.Cleanup(func() { _ = s.Close() })

	entries := []struct {
		cidr     string
		severity int
		source   string
	}{
		{"10.0.0.0/8", 1, "a"},
		{"10.1.0.0/16", 2, "a"},
		{"10.1.2.0/24", 3, "a"},
		{"10.1.2.128/25", 4, "a"},
		{"10.1.2.200/32", 5, "a"},
	}
	for _, e := range entries {
		require.NoError(t, s.WriteReputation(e.source, e.cidr, deny(e.severity)))
	}

	cases := []struct {
		ip           string
		wantSeverity int
		wantMatched  string
	}{
		{"10.1.2.200", 5, "10.1.2.200/32"},
		{"10.1.2.201", 4, "10.1.2.128/25"},
		{"10.1.2.5", 3, "10.1.2.0/24"},
		{"10.1.9.9", 2, "10.1.0.0/16"},
		{"10.200.0.1", 1, "10.0.0.0/8"},
	}
	for _, c := range cases {
		got, ok, err := s.Lookup(c.ip)
		require.NoError(t, err, c.ip)
		require.True(t, ok, c.ip)
		assert.Equal(t, c.wantSeverity, got.Severity, "%s severity", c.ip)
		assert.Equal(t, c.wantMatched, got.MatchedPrefix, "%s matched prefix", c.ip)
	}

	// Outside every network.
	_, ok, err := s.Lookup("11.0.0.1")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestLongestPrefixMatch_IPv6(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, Config{MaxEntries: -1, SweepInterval: -1})

	require.NoError(t, s.WriteReputation("a", "2001:db8::/32", deny(1)))
	require.NoError(t, s.WriteReputation("a", "2001:db8:1::/48", deny(2)))
	require.NoError(t, s.WriteReputation("a", "2001:db8:1:2::/64", deny(3)))
	require.NoError(t, s.WriteReputation("a", "2001:db8:1:2::5/128", deny(4)))

	cases := []struct {
		ip           string
		wantSeverity int
	}{
		{"2001:db8:1:2::5", 4},
		{"2001:db8:1:2::6", 3},
		{"2001:db8:1:3::1", 2},
		{"2001:db8:9::1", 1},
	}
	for _, c := range cases {
		got, ok, err := s.Lookup(c.ip)
		require.NoError(t, err, c.ip)
		require.True(t, ok, c.ip)
		assert.Equal(t, c.wantSeverity, got.Severity, c.ip)
	}

	_, ok, err := s.Lookup("2001:db9::1")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestConflictResolution_LongestPrefixBeatsPolicy(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, Config{ConflictPolicy: MaxSeverity, MaxEntries: -1, SweepInterval: -1})

	// The /8 carries the highest severity, yet the more specific /24 must win.
	require.NoError(t, s.WriteReputation("coarse", "10.0.0.0/8", deny(10)))
	require.NoError(t, s.WriteReputation("fine", "10.1.2.0/24", deny(1)))

	got, ok, err := s.Lookup("10.1.2.7")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, 1, got.Severity)
	assert.Equal(t, "10.1.2.0/24", got.MatchedPrefix)
	assert.Equal(t, "fine", got.Source)
}

func TestConflictResolution_SamePrefix(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("MaxSeverity", func(t *testing.T) {
		t.Parallel()
		s := newTestStore(t, Config{ConflictPolicy: MaxSeverity, MaxEntries: -1, SweepInterval: -1})
		require.NoError(t, s.WriteReputation("low", "10.0.0.0/8", &IPReputation{
			Status: ReputationSuspicious, Severity: 3, LastUpdated: base,
		}))
		require.NoError(t, s.WriteReputation("high", "10.0.0.0/8", &IPReputation{
			Status: ReputationDeny, Severity: 9, LastUpdated: base.Add(-time.Hour),
		}))
		got, ok, err := s.Lookup("10.1.2.3")
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, 9, got.Severity)
		assert.Equal(t, "high", got.Source)
	})

	t.Run("PriorityBased", func(t *testing.T) {
		t.Parallel()
		s := newTestStore(t, Config{
			ConflictPolicy: PriorityBased,
			SourcePriority: map[string]int{"trusted": 10, "untrusted": 1},
			MaxEntries:     -1,
			SweepInterval:  -1,
		})
		require.NoError(t, s.WriteReputation("untrusted", "10.0.0.0/8", &IPReputation{
			Status: ReputationDeny, Severity: 9, LastUpdated: base,
		}))
		require.NoError(t, s.WriteReputation("trusted", "10.0.0.0/8", &IPReputation{
			Status: ReputationAllow, Severity: 1, LastUpdated: base.Add(-time.Hour),
		}))
		got, ok, err := s.Lookup("10.1.2.3")
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, "trusted", got.Source)
		assert.Equal(t, ReputationAllow, got.Status)
	})

	t.Run("LastWriteWins", func(t *testing.T) {
		t.Parallel()
		s := newTestStore(t, Config{ConflictPolicy: LastWriteWins, MaxEntries: -1, SweepInterval: -1})
		require.NoError(t, s.WriteReputation("old", "10.0.0.0/8", &IPReputation{
			Status: ReputationDeny, Severity: 9, LastUpdated: base.Add(-time.Hour),
		}))
		require.NoError(t, s.WriteReputation("new", "10.0.0.0/8", &IPReputation{
			Status: ReputationAllow, Severity: 1, LastUpdated: base,
		}))
		got, ok, err := s.Lookup("10.1.2.3")
		require.NoError(t, err)
		require.True(t, ok)
		assert.Equal(t, "new", got.Source)
	})

	t.Run("deterministic on full tie", func(t *testing.T) {
		t.Parallel()
		// Identical timestamps and severities: the winner must not depend on map
		// iteration order, so repeated lookups agree.
		s := newTestStore(t, Config{ConflictPolicy: LastWriteWins, MaxEntries: -1, SweepInterval: -1})
		for _, src := range []string{"alpha", "bravo", "charlie", "delta"} {
			require.NoError(t, s.WriteReputation(src, "10.0.0.0/8", &IPReputation{
				Status: ReputationDeny, Severity: 5, LastUpdated: base,
			}))
		}
		first, _, err := s.Lookup("10.1.1.1")
		require.NoError(t, err)
		for i := 0; i < 50; i++ {
			got, _, err := s.Lookup("10.1.1.1")
			require.NoError(t, err)
			require.NotNil(t, got)
			assert.Equal(t, first.Source, got.Source)
		}
	})
}

func TestNormalization(t *testing.T) {
	t.Parallel()

	// Write one canonical entry per group, then confirm every spelling of the
	// same address matches it.
	groups := []struct {
		write   string
		aliases []string
	}{
		{
			write:   "1.2.3.4",
			aliases: []string{"1.2.3.4", "::ffff:1.2.3.4", "001.002.003.004", "[1.2.3.4]", "1.2.3.4:443", "[1.2.3.4]:8443"},
		},
		{
			write:   "2001:db8::1",
			aliases: []string{"2001:0db8:0000:0000:0000:0000:0000:0001", "[2001:db8::1]", "[2001:db8::1]:443"},
		},
	}

	for _, g := range groups {
		s := newTestStore(t, Config{MaxEntries: -1, SweepInterval: -1})
		require.NoError(t, s.WriteReputation("feed", g.write, deny(7)))
		for _, alias := range g.aliases {
			got, ok, err := s.Lookup(alias)
			require.NoError(t, err, alias)
			require.True(t, ok, alias)
			assert.Equal(t, 7, got.Severity, alias)
		}
	}
}

func TestNormalization_InvalidInput(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, Config{MaxEntries: -1, SweepInterval: -1})

	for _, bad := range []string{
		"", "not-an-ip", "1.2.3", "1.2.3.4.5", "256.1.1.1", "10.0.0.0/33",
		"10.0.0.0/-1", "2001:db8::/129", "10.1.2.3/8", "::1/130", "[::1",
	} {
		err := s.WriteReputation("feed", bad, deny(1))
		assert.Error(t, err, "write %q", bad)

		_, _, err = s.Lookup(bad)
		assert.Error(t, err, "lookup %q", bad)
		if err != nil {
			assert.NotErrorIs(t, err, datastores.ErrNotFound, "lookup %q", bad)
		}
	}

	// Nothing was silently written as an "unmatchable" key.
	assert.Equal(t, 0, s.Stats().Entries)
}

func TestNormalization_IPv4MappedNetwork(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, Config{MaxEntries: -1, SweepInterval: -1})

	// An IPv4-mapped network is the same network as its IPv4 spelling.
	require.NoError(t, s.WriteReputation("feed", "::ffff:10.0.0.0/104", deny(5)))

	got, ok, err := s.Lookup("10.1.2.3")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, "10.0.0.0/8", got.MatchedPrefix)
}

func TestExpiry(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	s := NewIPReputationStoreWithConfig(Config{MaxEntries: -1, SweepInterval: -1, Clock: clock.Now})
	t.Cleanup(func() { _ = s.Close() })

	require.NoError(t, s.WriteReputation("feed", "10.0.0.0/8", &IPReputation{
		Status: ReputationDeny, Severity: 5, TTL: time.Hour,
	}))
	require.NoError(t, s.WriteReputation("feed", "192.168.0.0/16", &IPReputation{
		Status: ReputationDeny, Severity: 5, // no TTL: never expires
	}))

	got, ok, err := s.Lookup("10.1.2.3")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, clock.Now().Add(time.Hour), got.ExpiresAt)

	// Just before expiry the entry still matches.
	clock.Advance(59 * time.Minute)
	_, ok, err = s.Lookup("10.1.2.3")
	require.NoError(t, err)
	require.True(t, ok)

	// At expiry the entry stops matching.
	clock.Advance(time.Minute)
	_, ok, err = s.Lookup("10.1.2.3")
	require.NoError(t, err)
	assert.False(t, ok, "expired entry must not match")

	// The never-expiring entry is unaffected.
	_, ok, err = s.Lookup("192.168.1.1")
	require.NoError(t, err)
	assert.True(t, ok)

	// Reclamation removes the expired entry from memory.
	removed := s.SweepExpired(clock.Now())
	assert.Equal(t, 1, removed)
	assert.Equal(t, int64(1), s.GetMetrics().ItemCount)
	assert.Equal(t, uint64(1), s.Stats().ExpiredReclaimed)

	// Reclaiming again is a no-op.
	assert.Equal(t, 0, s.SweepExpired(clock.Now()))
	assert.Equal(t, uint64(1), s.Stats().ExpiredReclaimed)
}

func TestExpiry_DefaultTTL(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	s := NewIPReputationStoreWithConfig(Config{
		DefaultTTL:    10 * time.Minute,
		MaxEntries:    -1,
		SweepInterval: -1,
		Clock:         clock.Now,
	})
	t.Cleanup(func() { _ = s.Close() })

	require.NoError(t, s.WriteReputation("feed", "10.0.0.0/8", deny(5)))
	got, ok, err := s.Lookup("10.1.2.3")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, clock.Now().Add(10*time.Minute), got.ExpiresAt)

	clock.Advance(11 * time.Minute)
	_, ok, err = s.Lookup("10.1.2.3")
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestRevocation(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, Config{MaxEntries: -1, SweepInterval: -1})

	require.NoError(t, s.WriteReputation("feedA", "10.0.0.0/8", deny(3)))
	require.NoError(t, s.WriteReputation("feedB", "10.0.0.0/8", &IPReputation{
		Status: ReputationAllow, Severity: 1,
	}))
	require.NoError(t, s.WriteReputation("feedA", "192.168.0.0/16", deny(3)))

	// A lookup currently resolves to one of the two sources; capture which.
	before, ok, err := s.Lookup("10.1.1.1")
	require.NoError(t, err)
	require.True(t, ok)

	// Revoking feedA removes all its entries immediately.
	require.NoError(t, s.Clear("feedA"))

	after, ok, err := s.Lookup("10.1.1.1")
	require.NoError(t, err)
	require.True(t, ok, "feedB entry for the same prefix must remain")
	assert.Equal(t, "feedB", after.Source)
	assert.Equal(t, ReputationAllow, after.Status)

	// feedA's other prefix is gone.
	_, ok, err = s.Lookup("192.168.1.1")
	require.NoError(t, err)
	assert.False(t, ok)

	// Clearing an absent source is a no-op.
	require.NoError(t, s.Clear("feedA"))
	assert.NotEqual(t, before.Source, "feedA")

	sources, err := s.ListSources()
	require.NoError(t, err)
	assert.Equal(t, []string{"feedB"}, sources)
}

func TestDelete_PrefixKey(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, Config{MaxEntries: -1, SweepInterval: -1})

	require.NoError(t, s.WriteReputation("feed", "10.1.2.0/24", deny(3)))
	require.NoError(t, s.WriteReputation("feed", "10.1.2.7", deny(4)))

	key := ipAddressKeyAny(t, "10.1.2.0/24")
	require.NoError(t, s.Delete("feed", key))

	// The exact /32 entry survives and still matches.
	got, ok, err := s.Lookup("10.1.2.7")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, 4, got.Severity)

	// Other addresses under the deleted network no longer match.
	_, ok, err = s.Lookup("10.1.2.8")
	require.NoError(t, err)
	assert.False(t, ok)

	// Deleting a malformed key is an error, not a silent no-op.
	assert.Error(t, s.Delete("feed", ipAddressKeyAny(t, "not-an-ip")))
}

func TestCapacityEviction(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, Config{MaxEntries: 100, SweepInterval: -1})

	const total = 250
	for i := 0; i < total; i++ {
		ip := fmt.Sprintf("10.%d.%d.0/24", i/256, i%256)
		require.NoError(t, s.WriteReputation("feed", ip, deny(5)))
	}

	stats := s.Stats()
	assert.LessOrEqual(t, stats.Entries, 100, "store must respect its capacity")
	assert.Greater(t, stats.Evicted, uint64(0), "evictions must be counted")
	assert.Equal(t, EvictionPolicyLRU, stats.EvictionPolicy)
	assert.False(t, stats.LastEviction.IsZero(), "eviction time must be recorded")

	// The most recently written entries survive and still match.
	for i := total - 10; i < total; i++ {
		ip := fmt.Sprintf("10.%d.%d.7", i/256, i%256)
		got, ok, err := s.Lookup(ip)
		require.NoError(t, err)
		require.True(t, ok, "recently written %s must still match", ip)
		assert.Equal(t, 5, got.Severity)
	}

	// Metrics expose the same counters.
	m := s.GetMetrics()
	assert.Equal(t, int64(stats.Entries), m.ItemCount)
	assert.Equal(t, int64(stats.Evicted), m.Extra["evicted"])
}

func TestCapacityEviction_PrefersExpired(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	s := NewIPReputationStoreWithConfig(Config{
		MaxEntries:    2,
		SweepInterval: -1,
		Clock:         clock.Now,
	})
	t.Cleanup(func() { _ = s.Close() })

	// Fill the store, then let the entries expire without sweeping them.
	require.NoError(t, s.WriteReputation("feed", "10.0.0.0/8", &IPReputation{
		Status: ReputationDeny, Severity: 1, TTL: time.Minute,
	}))
	require.NoError(t, s.WriteReputation("feed", "11.0.0.0/8", &IPReputation{
		Status: ReputationDeny, Severity: 1, TTL: time.Minute,
	}))
	clock.Advance(2 * time.Minute)

	// Writing a fresh entry must evict an expired one first, keeping the new one.
	require.NoError(t, s.WriteReputation("feed", "12.0.0.0/8", deny(9)))

	stats := s.Stats()
	assert.LessOrEqual(t, stats.Entries, 2)
	assert.Equal(t, uint64(1), stats.Evicted)

	got, ok, err := s.Lookup("12.0.0.1")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, 9, got.Severity)
}

func TestBatchLookup_MatchesIndividual(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, Config{MaxEntries: -1, SweepInterval: -1})

	for _, cidr := range []string{
		"10.0.0.0/8", "10.1.0.0/16", "192.168.0.0/16", "2001:db8::/32", "203.0.113.0/24",
	} {
		require.NoError(t, s.WriteReputation("feed", cidr, deny(6)))
	}

	ips := []string{
		"10.1.2.3", "10.2.3.4", "192.168.1.1", "2001:db8::1", "203.0.113.9", "8.8.8.8",
	}

	batch, err := s.LookupBatch(ips)
	require.NoError(t, err)

	for _, ip := range ips {
		individual, ok, err := s.Lookup(ip)
		require.NoError(t, err)
		if !ok {
			assert.NotContains(t, batch, ip)
			continue
		}
		require.Contains(t, batch, ip)
		assert.Equal(t, individual.Severity, batch[ip].Severity)
		assert.Equal(t, individual.MatchedPrefix, batch[ip].MatchedPrefix)
		assert.Equal(t, individual.Source, batch[ip].Source)
	}
}

func TestBatchLookup_ConsistentSnapshot(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, Config{MaxEntries: -1, SweepInterval: -1})

	// A batch must be resolved against one snapshot: no writer can interleave
	// and no entry can be reclaimed halfway through.
	require.NoError(t, s.WriteReputation("feed", "10.0.0.0/8", deny(5)))
	ips := make([]string, 2000)
	for i := range ips {
		ips[i] = fmt.Sprintf("10.%d.%d.1", i/256%256, i%256)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = s.WriteReputation("other", "10.0.0.0/8", deny(6))
			}
		}
	}()

	for round := 0; round < 50; round++ {
		batch, err := s.LookupBatch(ips)
		require.NoError(t, err)
		require.Len(t, batch, len(ips))
		for ip, rep := range batch {
			require.NotNil(t, rep, ip)
			assert.Equal(t, "10.0.0.0/8", rep.MatchedPrefix)
		}
	}
	close(stop)
	wg.Wait()
}

func TestBatchLookup_InvalidInputFailsWholeBatch(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, Config{MaxEntries: -1, SweepInterval: -1})
	require.NoError(t, s.WriteReputation("feed", "10.0.0.0/8", deny(5)))

	got, err := s.LookupBatch([]string{"10.1.2.3", "garbage"})
	require.Error(t, err)
	assert.Nil(t, got, "no partial results on error")
	assert.Contains(t, err.Error(), "entry 1")
}

func TestNormalization_QueryScaling(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, Config{MaxEntries: -1, SweepInterval: -1})

	// Populate with many unrelated networks.
	for i := 0; i < 5000; i++ {
		cidr := fmt.Sprintf("%d.%d.0.0/16", 1+i/256, i%256)
		require.NoError(t, s.WriteReputation("feed", cidr, deny(5)))
	}

	before := s.probes.Load()
	for i := 0; i < 1000; i++ {
		_, _, err := s.Lookup("172.16.5.5")
		require.NoError(t, err)
	}
	perQuery := (s.probes.Load() - before) / 1000

	// A query walks at most 33 prefix lengths (IPv4), independent of entry count.
	assert.LessOrEqual(t, perQuery, uint64(33), "lookup must be O(address bits)")
}

func TestConcurrentReadWrite(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	s := NewIPReputationStoreWithConfig(Config{
		MaxEntries:    2000,
		SweepInterval: -1,
		Clock:         clock.Now,
	})
	t.Cleanup(func() { _ = s.Close() })

	const writers = 8
	const readers = 8
	const iterations = 500

	var wg sync.WaitGroup
	var inconsistencies atomic.Int64

	// Writers constantly add, overwrite and clear entries.
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(id)))
			for i := 0; i < iterations; i++ {
				cidr := fmt.Sprintf("10.%d.%d.0/24", id, rng.Intn(256))
				rep := deny(1 + rng.Intn(10))
				if rng.Intn(10) == 0 {
					rep.TTL = time.Duration(rng.Intn(60)+1) * time.Second
				}
				if err := s.WriteReputation(fmt.Sprintf("src%d", id), cidr, rep); err != nil {
					t.Errorf("write: %v", err)
				}
				if i%97 == 0 {
					_ = s.Clear(fmt.Sprintf("src%d", id))
				}
			}
		}(w)
	}

	// Readers must always see a coherent answer: either a fully-formed match or
	// no match, never a zero-valued or partially populated one.
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(id + 100)))
			for i := 0; i < iterations; i++ {
				ip := fmt.Sprintf("10.%d.%d.%d", rng.Intn(writers), rng.Intn(256), rng.Intn(256))
				rep, ok, err := s.Lookup(ip)
				if err != nil {
					inconsistencies.Add(1)
					continue
				}
				if ok {
					if rep.Severity < 1 || rep.Severity > 10 || rep.Status != ReputationDeny {
						inconsistencies.Add(1)
					}
				}
				_, _ = s.LookupBatch([]string{ip, "10.0.0.1"})
				s.Stats()
			}
		}(r)
	}

	// A sweeper runs concurrently with everything else.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			clock.Advance(time.Second)
			s.SweepExpired(clock.Now())
		}
	}()

	wg.Wait()
	assert.Zero(t, inconsistencies.Load(), "readers observed inconsistent state")
	assert.LessOrEqual(t, s.Stats().Entries, 2000)
}

func TestMatchAPI(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, Config{MaxEntries: -1, SweepInterval: -1})
	require.NoError(t, s.WriteReputation("feed", "10.0.0.0/8", &IPReputation{
		Status: ReputationDeny, Severity: 8, Tags: []string{"botnet"}, Metadata: map[string]string{"k": "v"},
	}))

	match, err := s.Match("10.1.2.3")
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.0/8", match.Prefix)
	assert.Equal(t, "deny", match.Status)
	assert.Equal(t, 8, match.Severity)
	assert.Equal(t, []string{"botnet"}, match.Tags)
	assert.Equal(t, "feed", match.Source)

	_, err = s.Match("8.8.8.8")
	assert.ErrorIs(t, err, datastores.ErrNotFound)

	_, err = s.Match("garbage")
	assert.ErrorIs(t, err, datastores.ErrInvalidArgument)

	batch, err := s.MatchBatch([]string{"10.1.2.3", "8.8.8.8"})
	require.NoError(t, err)
	assert.Len(t, batch, 1)
	assert.Contains(t, batch, "10.1.2.3")
}

func TestWriteBatch_Atomic(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, Config{MaxEntries: -1, SweepInterval: -1})

	good := map[string]*IPReputation{
		"10.0.0.0/8":     deny(1),
		"192.168.0.0/16": deny(2),
	}
	require.NoError(t, s.WriteReputationBatch("feed", good))
	assert.Equal(t, 2, s.Stats().Entries)

	// A batch containing one malformed prefix writes nothing at all.
	bad := map[string]*IPReputation{
		"172.16.0.0/12": deny(3),
		"broken/999":    deny(4),
	}
	err := s.WriteReputationBatch("feed", bad)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "broken/999")
	assert.Equal(t, 2, s.Stats().Entries, "no partial write may occur")

	_, ok, err := s.Lookup("172.16.1.1")
	require.NoError(t, err)
	assert.False(t, ok, "valid entry from a rejected batch must not be visible")
}

func TestWriteBatch_ReportsIndex(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, Config{MaxEntries: -1, SweepInterval: -1})

	entries := []*datastores.DataEntry{
		makeEntry(t, "10.0.0.0/8", ReputationDeny, 1),
		makeEntry(t, "10.1.0.0/16", ReputationDeny, 1),
		makeEntry(t, "not-a-prefix", ReputationDeny, 1),
	}
	err := s.WriteBatch("feed", entries)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "entry 2", "error must identify the offending index")
	assert.Equal(t, 0, s.Stats().Entries)
}

func TestIsDeniedIsAllowed(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, Config{MaxEntries: -1, SweepInterval: -1})
	require.NoError(t, s.WriteReputation("feed", "10.0.0.0/8", deny(5)))
	require.NoError(t, s.WriteReputation("feed", "192.168.0.0/16", &IPReputation{
		Status: ReputationAllow, Severity: 1,
	}))

	assert.True(t, s.IsDenied("10.1.2.3"))
	assert.False(t, s.IsAllowed("10.1.2.3"))
	assert.True(t, s.IsAllowed("192.168.1.1"))
	assert.False(t, s.IsDenied("192.168.1.1"))
	assert.False(t, s.IsDenied("8.8.8.8"))
	// Malformed input is simply "not denied" for the legacy helpers.
	assert.False(t, s.IsDenied("garbage"))
}

func TestStatsAndMetrics(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	s := NewIPReputationStoreWithConfig(Config{MaxEntries: 10, SweepInterval: -1, Clock: clock.Now})
	t.Cleanup(func() { _ = s.Close() })

	require.NoError(t, s.WriteReputation("a", "10.0.0.0/8", &IPReputation{
		Status: ReputationDeny, Severity: 5, TTL: time.Minute,
	}))
	require.NoError(t, s.WriteReputation("b", "192.168.0.0/16", deny(5)))

	_, _, _ = s.Lookup("10.1.1.1")
	_, _, _ = s.Lookup("8.8.8.8")

	stats := s.Stats()
	assert.Equal(t, 2, stats.Entries)
	assert.Equal(t, 2, stats.LiveEntries)
	assert.Equal(t, 2, stats.Prefixes)
	assert.Equal(t, 2, stats.Sources)
	assert.Equal(t, 10, stats.Capacity)
	assert.Equal(t, uint64(2), stats.Queries)
	assert.Equal(t, uint64(1), stats.Hits)
	assert.Equal(t, uint64(1), stats.Misses)

	clock.Advance(2 * time.Minute)
	assert.Equal(t, 1, s.SweepExpired(clock.Now()))

	stats = s.Stats()
	assert.Equal(t, 1, stats.Entries)
	assert.Equal(t, uint64(1), stats.ExpiredReclaimed)

	m := s.GetMetrics()
	assert.Equal(t, int64(1), m.ItemCount)
	assert.Equal(t, int64(1), m.Extra["expired_reclaimed"])
	assert.Equal(t, int64(10), m.Extra["capacity"])
}

func TestSweeperLifecycle(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	s := NewIPReputationStoreWithConfig(Config{
		SweepInterval: 10 * time.Millisecond,
		MaxEntries:    -1,
		Clock:         clock.Now,
	})
	require.NoError(t, s.Initialize(context.TODO()))
	require.NoError(t, s.Initialize(context.TODO()), "starting twice must be a no-op")

	require.NoError(t, s.WriteReputation("feed", "10.0.0.0/8", &IPReputation{
		Status: ReputationDeny, Severity: 5, TTL: time.Second,
	}))
	clock.Advance(2 * time.Second)

	require.Eventually(t, func() bool {
		return s.Stats().ExpiredReclaimed == 1
	}, 2*time.Second, 5*time.Millisecond, "sweeper must reclaim expired entries")

	require.NoError(t, s.Close())
	require.NoError(t, s.Close(), "closing twice must be safe")
}

func TestConstructorCompatibility(t *testing.T) {
	t.Parallel()
	// The historical constructor still works and returns a usable store.
	s := NewIPReputationStore(MaxSeverity, map[string]int{"trusted": 10})
	require.NoError(t, s.WriteReputation("feed", "10.0.0.0/8", deny(5)))
	got, ok := s.GetReputation("10.1.2.3")
	require.True(t, ok)
	assert.Equal(t, 5, got.Severity)
}

func TestExactAddressCompatibility(t *testing.T) {
	t.Parallel()
	// Callers that write and read single addresses keep exactly the same
	// behaviour and result shape: no prefix annotation, same fields.
	s := newTestStore(t, Config{MaxEntries: -1, SweepInterval: -1})
	require.NoError(t, s.WriteReputation("feed", "1.2.3.4", &IPReputation{
		Status: ReputationDeny, Severity: 8, Tags: []string{"malware"},
		Metadata: map[string]string{"info": "test"},
	}))

	rep, found := s.GetReputation("1.2.3.4")
	require.True(t, found)
	assert.Equal(t, "1.2.3.4", rep.IP)
	assert.Empty(t, rep.MatchedPrefix, "exact matches carry no prefix annotation")
	assert.Equal(t, ReputationDeny, rep.Status)
	assert.Equal(t, 8, rep.Severity)
	assert.Equal(t, []string{"malware"}, rep.Tags)
	assert.Equal(t, map[string]string{"info": "test"}, rep.Metadata)
	assert.True(t, rep.ExpiresAt.IsZero(), "no TTL means no expiry")

	// A neighbouring address must not match a single-address entry.
	_, found = s.GetReputation("1.2.3.5")
	assert.False(t, found)
}

func TestMetrics_QueryCounters(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, Config{MaxEntries: -1, SweepInterval: -1})
	require.NoError(t, s.WriteReputation("feed", "10.0.0.0/8", deny(5)))

	_, _, _ = s.Lookup("10.1.2.3") // hit
	_, _, _ = s.Lookup("8.8.8.8")  // miss
	_, _, _ = s.Lookup("bad")      // error

	m := s.GetMetrics()
	assert.Equal(t, uint64(1), m.CacheHits)
	assert.Equal(t, uint64(1), m.CacheMisses)
	assert.Equal(t, uint64(1), m.SuccessCount)
	assert.Equal(t, uint64(1), m.ErrorCount, "malformed queries are counted as errors")
	assert.Equal(t, int64(3), m.Extra["queries"])
}

func TestPrefixValidation_HostBits(t *testing.T) {
	t.Parallel()
	s := newTestStore(t, Config{MaxEntries: -1, SweepInterval: -1})

	// Host bits set is a typo, not a request to widen the network.
	err := s.WriteReputation("feed", "10.1.2.3/8", deny(1))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did you mean", "error should suggest the masked form")

	// The masked form is accepted.
	require.NoError(t, s.WriteReputation("feed", "10.0.0.0/8", deny(1)))
}

// helpers

func ipAddressKeyAny(t *testing.T, ip string) *anypb.Any {
	t.Helper()
	key, err := anypb.New(&datastores.IPAddressKey{Ip: ip})
	require.NoError(t, err)
	return key
}

func makeEntry(t *testing.T, ip string, status ReputationStatus, severity int) *datastores.DataEntry {
	t.Helper()
	rep, err := anypb.New(&datastores.IPReputation{
		Status:   datastores.ReputationStatus(status),
		Severity: int32(severity),
	})
	require.NoError(t, err)
	return &datastores.DataEntry{Key: ipAddressKeyAny(t, ip), Data: rep}
}

func TestNormalizeKey_TableDriven(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"1.2.3.4", "1.2.3.4", false},
		{"1.2.3.4:443", "1.2.3.4", false},
		{"[1.2.3.4]", "1.2.3.4", false},
		{"[1.2.3.4]:443", "1.2.3.4", false},
		{"001.002.003.004", "1.2.3.4", false},
		{"::ffff:1.2.3.4", "1.2.3.4", false},
		{"2001:db8::1", "2001:db8::1", false},
		{"2001:0db8:0:0:0:0:0:1", "2001:db8::1", false},
		{"[2001:db8::1]", "2001:db8::1", false},
		{"[2001:db8::1]:8080", "2001:db8::1", false},
		{"fe80::1%eth0", "fe80::1", false},
		{"10.0.0.0/8", "10.0.0.0/8", false},
		{"10.0.0.1/8", "", true},
		{"2001:db8::/32", "2001:db8::/32", false},
		{"::ffff:10.0.0.0/104", "10.0.0.0/8", false},
		{"::1/128", "::1/128", false},
		{"", "", true},
		{"abc", "", true},
		{"2001:db8::1:443", "2001:db8::1:443", false}, // a valid IPv6 address, not host:port
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			key, err := normalizeKey(tt.in)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, key.String())
		})
	}
}

// Verify the index prefix for an address is its full-length prefix.
func TestIndexPrefix(t *testing.T) {
	t.Parallel()
	k, err := normalizeKey("10.1.2.3")
	require.NoError(t, err)
	assert.Equal(t, netip.MustParsePrefix("10.1.2.3/32"), k.indexPrefix())

	k, err = normalizeKey("2001:db8::1")
	require.NoError(t, err)
	assert.Equal(t, netip.MustParsePrefix("2001:db8::1/128"), k.indexPrefix())

	k, err = normalizeKey("10.0.0.0/8")
	require.NoError(t, err)
	assert.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), k.indexPrefix())
}
