package grpc

import (
	"context"
	"testing"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	dsstore "github.com/aquasecurity/tracee/pkg/datastores"
	"github.com/aquasecurity/tracee/pkg/datastores/ipreputation"
)

// TestDataStoreService_IPReputationEndToEnd drives the production gRPC service
// with a real IP reputation store: a feed writes networks over the wire, a
// detector-facing lookup then resolves them by longest prefix.
func TestDataStoreService_IPReputationEndToEnd(t *testing.T) {
	store := ipreputation.NewIPReputationStoreWithConfig(ipreputation.Config{
		MaxEntries:    -1,
		SweepInterval: -1,
	})
	t.Cleanup(func() { _ = store.Close() })

	runtime := dsstore.NewWritableStoreRuntime(datastoresapiName(), store)
	svc := NewDataStoreService(runtime)

	keyAny, err := anypb.New(&datastores.IPAddressKey{Ip: "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	dataAny, err := anypb.New(&datastores.IPReputation{
		Status:   datastores.ReputationStatus_REPUTATION_DENY,
		Severity: 8,
		Tags:     []string{"botnet"},
		Ttl:      durationpb.New(3600e9),
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = svc.WriteData(context.Background(), &datastores.WriteDataRequest{
		StoreName: datastoresapiName(),
		Source:    "external_feed",
		Entry:     &datastores.DataEntry{Key: keyAny, Data: dataAny},
	})
	if err != nil {
		t.Fatalf("write: %v", err)
	}

	// Longest-prefix lookup by an address inside the network.
	match, err := store.Match("10.1.2.3")
	if err != nil {
		t.Fatalf("match: %v", err)
	}
	if match.Prefix != "10.0.0.0/8" || match.Status != "deny" || match.Severity != 8 {
		t.Fatalf("unexpected match: %+v", match)
	}

	// The feed is visible via ListSources and disappears on ClearSource.
	resp, err := svc.ListSources(context.Background(), &datastores.ListSourcesRequest{StoreName: datastoresapiName()})
	if err != nil {
		t.Fatalf("list sources: %v", err)
	}
	if len(resp.Sources) != 1 || resp.Sources[0] != "external_feed" {
		t.Fatalf("unexpected sources: %v", resp.Sources)
	}

	if _, err := svc.ClearSource(context.Background(), &datastores.ClearSourceRequest{
		StoreName: datastoresapiName(),
		Source:    "external_feed",
	}); err != nil {
		t.Fatalf("clear source: %v", err)
	}

	if _, err := store.Match("10.1.2.3"); err == nil {
		t.Fatal("expected ErrNotFound after revoking the feed")
	}
}

// TestDataStoreService_IPReputationRejectsMalformedPrefix verifies that a bad
// prefix is rejected at the gRPC boundary instead of being stored as an entry
// that can never match.
func TestDataStoreService_IPReputationRejectsMalformedPrefix(t *testing.T) {
	store := ipreputation.NewIPReputationStoreWithConfig(ipreputation.Config{
		MaxEntries:    -1,
		SweepInterval: -1,
	})
	t.Cleanup(func() { _ = store.Close() })

	svc := NewDataStoreService(dsstore.NewWritableStoreRuntime(datastoresapiName(), store))

	keyAny, _ := anypb.New(&datastores.IPAddressKey{Ip: "10.1.2.3/8"}) // host bits set
	dataAny, _ := anypb.New(&datastores.IPReputation{
		Status:   datastores.ReputationStatus_REPUTATION_DENY,
		Severity: 5,
	})

	_, err := svc.WriteData(context.Background(), &datastores.WriteDataRequest{
		StoreName: datastoresapiName(),
		Source:    "bad_feed",
		Entry:     &datastores.DataEntry{Key: keyAny, Data: dataAny},
	})
	if err == nil {
		t.Fatal("expected an error for a malformed prefix")
	}
	if n := store.Stats().Entries; n != 0 {
		t.Fatalf("malformed entry must not be stored, have %d entries", n)
	}
}

func datastoresapiName() string { return "ip_reputation" }
