package datastores

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
	"github.com/aquasecurity/tracee/pkg/datastores/ipreputation"
)

func TestRegistry_IPReputation(t *testing.T) {
	t.Run("never nil", func(t *testing.T) {
		reg := NewRegistry()
		// Before any registration the accessor returns a non-nil store whose
		// lookups report "unavailable" rather than panicking.
		store := reg.IPReputation()
		require.NotNil(t, store)
		assert.False(t, reg.IsAvailable(datastores.IPReputationStoreName))
	})

	t.Run("registered store is exposed", func(t *testing.T) {
		reg := NewRegistry()
		store := ipreputation.NewIPReputationStoreWithConfig(ipreputation.Config{
			MaxEntries:    -1,
			SweepInterval: -1,
		})
		t.Cleanup(func() { _ = store.Close() })
		require.NoError(t, store.WriteReputation("feed", "10.0.0.0/8", &ipreputation.IPReputation{
			Status: ipreputation.ReputationDeny, Severity: 7,
		}))

		require.NoError(t, reg.RegisterStore(datastores.IPReputationStoreName, store, false))
		assert.True(t, reg.IsAvailable(datastores.IPReputationStoreName))

		match, err := reg.IPReputation().Match("10.1.2.3")
		require.NoError(t, err)
		assert.Equal(t, 7, match.Severity)

		// The typed accessor and the runtime both resolve to the same store.
		assert.Same(t, store, reg.GetIPReputationStore())
		runtime := reg.GetIPReputationRuntime()
		require.NotNil(t, runtime)
		assert.Equal(t, []string{datastores.IPReputationStoreName}, runtime.Stores())

		sources, err := runtime.ListSources(datastores.IPReputationStoreName)
		require.NoError(t, err)
		assert.Equal(t, []string{"feed"}, sources)
	})

	t.Run("metrics are readable through the registry", func(t *testing.T) {
		reg := NewRegistry()
		store := ipreputation.NewIPReputationStoreWithConfig(ipreputation.Config{
			MaxEntries:    5,
			SweepInterval: -1,
		})
		t.Cleanup(func() { _ = store.Close() })
		require.NoError(t, reg.RegisterStore(datastores.IPReputationStoreName, store, false))

		metrics, err := reg.GetMetrics(datastores.IPReputationStoreName)
		require.NoError(t, err)
		assert.Equal(t, int64(0), metrics.ItemCount)
		assert.Equal(t, int64(5), metrics.Extra["capacity"])
	})
}
