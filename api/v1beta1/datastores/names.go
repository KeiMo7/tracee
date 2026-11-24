package datastores

// Datastore names
const (
	Process   = "process"
	Container = "container"
	Symbol    = "symbol"
	DNS       = "dns"
	System    = "system"
	Syscall   = "syscall"
	// IPReputationStoreName is the name of the IP reputation datastore. It is
	// spelled differently from the other name constants because the generated
	// protobuf message already occupies the identifier IPReputation.
	IPReputationStoreName = "ip_reputation"
)
