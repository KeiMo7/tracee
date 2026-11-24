package yaml

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1"
	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/pkg/datastores/ipreputation"
)

// newIPReputationRegistry returns a registry backed by a real IP reputation
// store with a small, known data set.
func newIPReputationRegistry(t *testing.T) *mockRegistry {
	t.Helper()
	store := ipreputation.NewIPReputationStoreWithConfig(ipreputation.Config{
		MaxEntries:    -1,
		SweepInterval: -1,
	})
	t.Cleanup(func() { _ = store.Close() })

	require.NoError(t, store.WriteReputation("feed", "10.0.0.0/8", &ipreputation.IPReputation{
		Status: ipreputation.ReputationSuspicious, Severity: 4,
		Tags: []string{"scanner"}, Source: "feed",
	}))
	require.NoError(t, store.WriteReputation("feed", "203.0.113.0/24", &ipreputation.IPReputation{
		Status: ipreputation.ReputationDeny, Severity: 9,
		Tags: []string{"c2"}, Source: "feed",
	}))

	return &mockRegistry{ipReputationStore: store}
}

func TestIPMatchFunction(t *testing.T) {
	registry := newIPReputationRegistry(t)
	env, err := createCELEnvironment(nil, registry)
	require.NoError(t, err)

	// Longest-prefix match: 203.0.113.9 is inside the /24, not just the /8.
	prog, err := CompileExpression(env, `ip.match("203.0.113.9").severity`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, int64(9), result)

	// The matched prefix is exposed so a condition can distinguish entries.
	prog, err = CompileExpression(env, `ip.match("203.0.113.9").prefix`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "203.0.113.0/24", result)

	// A coarse /8 match for an address outside the /24.
	prog, err = CompileExpression(env, `ip.match("10.9.8.7").prefix`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "10.0.0.0/8", result)

	// No match yields null.
	prog, err = CompileExpression(env, `ip.match("8.8.8.8") == null`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, true, result)

	// Malformed input surfaces as an evaluation error, not a silent miss.
	prog, err = CompileExpression(env, `ip.match("not-an-ip")`)
	require.NoError(t, err)
	_, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	assert.Error(t, err)
}

func TestIPIsMaliciousFunction(t *testing.T) {
	registry := newIPReputationRegistry(t)
	env, err := createCELEnvironment(nil, registry)
	require.NoError(t, err)

	cases := map[string]bool{
		"203.0.113.9": true,  // deny
		"10.1.2.3":    true,  // suspicious
		"8.8.8.8":     false, // no match
	}
	for ip, want := range cases {
		prog, err := CompileExpression(env, `ip.isMalicious("`+ip+`")`)
		require.NoError(t, err, ip)
		result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
		require.NoError(t, err, ip)
		assert.Equal(t, want, result, ip)
	}
}

func TestIPMatchBatchFunction(t *testing.T) {
	registry := newIPReputationRegistry(t)
	env, err := createCELEnvironment(nil, registry)
	require.NoError(t, err)

	prog, err := CompileExpression(env,
		`ip.matchBatch(["203.0.113.9", "10.1.2.3", "8.8.8.8"]).size()`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, int64(2), result, "only matching addresses are returned")

	prog, err = CompileExpression(env,
		`ip.matchBatch(["203.0.113.9"])["203.0.113.9"].status`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, "deny", result)
}

func TestIPFunctionsNilSafe(t *testing.T) {
	// Validation mode compiles without a registry; calls return null/false.
	env, err := createCELEnvironment(nil, nil)
	require.NoError(t, err)

	prog, err := CompileExpression(env, `ip.match("10.0.0.1") == null`)
	require.NoError(t, err)
	result, err := EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, true, result)

	prog, err = CompileExpression(env, `ip.isMalicious("10.0.0.1") == false`)
	require.NoError(t, err)
	result, err = EvaluateExpression(prog, &v1beta1.Event{}, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, true, result)
}

// TestIPMatchFromEvent drives the function the way a detector would: the
// address comes from event data and the result gates a detection.
func TestIPMatchFromEvent(t *testing.T) {
	registry := newIPReputationRegistry(t)
	env, err := createCELEnvironment(nil, registry)
	require.NoError(t, err)

	prog, err := CompileExpression(env,
		`ip.match(getEventData("dst_ip")) != null && ip.match(getEventData("dst_ip")).severity >= 8`)
	require.NoError(t, err)

	event := &v1beta1.Event{
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("dst_ip", "203.0.113.9"),
		},
	}
	result, err := EvaluateExpression(prog, event, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, true, result)

	cleanEvent := &v1beta1.Event{
		Data: []*v1beta1.EventValue{
			v1beta1.NewStringValue("dst_ip", "8.8.8.8"),
		},
	}
	result, err = EvaluateExpression(prog, cleanEvent, nil, 5*time.Millisecond)
	require.NoError(t, err)
	assert.Equal(t, false, result)
}

// Ensure the mock registry still satisfies the interface after the addition.
var _ datastores.Registry = (*mockRegistry)(nil)
