package datastores

import "time"

// ProcessInfo contains information about a process
type ProcessInfo struct {
	// Unique identifiers (hashes)
	UniqueId       uint32 // Process unique ID (hash) - matches protobuf unique_id
	ParentUniqueId uint32 // Parent process unique ID (hash) - efficient ancestry

	// Process IDs
	HostPid  uint32 // Host namespace PID (root namespace) - matches protobuf host_pid
	Pid      uint32 // Process namespace PID (container if containerized) - matches protobuf pid
	HostPpid uint32 // Host namespace parent PID
	Ppid     uint32 // Process namespace parent PID

	// Process metadata
	Name      string    // Binary name only: "bash"
	Exe       string    // Full path: "/usr/bin/bash"
	StartTime time.Time // Process start time
	ExitTime  time.Time // Process exit time (zero if still running)

	// User/Group
	UID uint32 // User ID - matches protobuf real_user.id
	GID uint32 // Group ID
	// Phase 2: CmdLine/Args (memory impact)
}

// ContainerInfo contains information about a container
type ContainerInfo struct {
	ID          string      // Container ID
	Name        string      // Container name
	Image       string      // Container image
	ImageDigest string      // Image digest
	Runtime     string      // Runtime (docker, containerd, crio)
	StartTime   time.Time   // Container start time
	Pod         *K8sPodInfo // Kubernetes pod info (nil for non-K8s containers)
	// Phase 2: Labels (requires runtime extraction), Status, PID, Env, Mounts
}

// K8sPodInfo contains Kubernetes pod metadata
type K8sPodInfo struct {
	Name      string // Pod name
	UID       string // Pod UID
	Namespace string // Pod namespace
	Sandbox   bool   // Whether this is a sandbox container
}

// SymbolInfo contains information about a kernel symbol
type SymbolInfo struct {
	Name    string // Symbol name
	Address uint64 // Symbol address
	Module  string // Module name (or "system" for kernel symbols)
}

// DNSResponse contains DNS query response information
type DNSResponse struct {
	Query   string   // DNS query (domain name)
	IPs     []string // Resolved IP addresses
	Domains []string // Resolved domain names (for reverse lookups)
}

// IPReputationMatch is the result of an IP reputation lookup.
//
// A lookup that hits an exact-address entry leaves Prefix empty and sets IP to
// the canonical address. A lookup that hits a network entry sets Prefix to the
// matched network in CIDR notation and IP to that network's base address, so
// callers can tell which feed entry was responsible.
type IPReputationMatch struct {
	Query       string            // Address or network as supplied by the caller
	IP          string            // Canonical matched address or network base
	Prefix      string            // Matched network in CIDR form, empty for exact entries
	Status      string            // "allow", "deny", "suspicious" or "unknown"
	Severity    int               // 1-10 severity score
	Tags        []string          // Feed tags, e.g. ["botnet", "c2"]
	Source      string            // Source that supplied the winning entry
	LastUpdated time.Time         // When the source last updated the entry
	ExpiresAt   time.Time         // When the entry stops matching; zero means never
	Metadata    map[string]string // Additional key-value metadata
}

// HealthStatus represents the health state of a datastore
type HealthStatus int

const (
	HealthUnknown HealthStatus = iota
	HealthHealthy
	HealthUnhealthy
)

func (h HealthStatus) String() string {
	switch h {
	case HealthHealthy:
		return "healthy"
	case HealthUnhealthy:
		return "unhealthy"
	default:
		return "unknown"
	}
}

// HealthInfo contains health information about a datastore
type HealthInfo struct {
	Status    HealthStatus // Current health status
	Message   string       // Empty if healthy, error details if not
	LastCheck time.Time    // When health was last checked
}

// DataStoreMetrics contains metrics about datastore operations
type DataStoreMetrics struct {
	ItemCount    int64     // Number of items in store
	SuccessCount uint64    // Number of successful requests
	ErrorCount   uint64    // Number of failed requests
	CacheHits    uint64    // Number of cache hits (if applicable)
	CacheMisses  uint64    // Number of cache misses (if applicable)
	LastAccess   time.Time // Last access time

	// Extra carries store-specific counters that do not fit the common fields,
	// such as expiry reclamations and capacity evictions. It is nil for stores
	// that do not report any.
	Extra map[string]int64
}

// DataStoreMetadata contains metadata about a datastore
type DataStoreMetadata struct {
	Name        string         // Human-readable name (e.g., "processes")
	Description string         // What this store provides
	Config      map[string]any // Store-specific configuration
}

// SystemInfo contains immutable system-level information collected at startup
type SystemInfo struct {
	Architecture    string            // CPU architecture (e.g., "x86_64", "aarch64")
	KernelRelease   string            // Kernel version (e.g., "5.15.0-generic")
	Hostname        string            // System hostname
	BootTime        time.Time         // System boot time
	TraceeStartTime time.Time         // Time when Tracee started
	OSName          string            // OS name (e.g., "Ubuntu")
	OSVersion       string            // OS version (e.g., "22.04")
	OSPrettyName    string            // Human-readable full OS name (e.g., "Ubuntu 22.04 LTS")
	TraceeVersion   string            // Tracee version string
	InitNamespaces  map[string]uint32 // Init process namespaces (cgroup, ipc, mnt, net, pid, etc.)
}
