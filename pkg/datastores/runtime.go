package datastores

import (
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/aquasecurity/tracee/api/v1beta1/datastores"
)

// writableStoreRuntime adapts a single WritableStore to the Runtime interface so
// it can be served by the gRPC DataStoreService. It is used for core writable
// stores (such as ip_reputation) that Tracee owns itself, as opposed to stores
// provided by extensions.
type writableStoreRuntime struct {
	name  string
	store datastores.WritableStore
}

// NewWritableStoreRuntime returns a Runtime that owns exactly one writable
// store, identified by name.
func NewWritableStoreRuntime(name string, store datastores.WritableStore) datastores.Runtime {
	return &writableStoreRuntime{name: name, store: store}
}

func (r *writableStoreRuntime) guard(storeName string) error {
	if storeName != r.name {
		return datastores.ErrRuntimeStoreNotFound
	}
	return nil
}

func (r *writableStoreRuntime) Stores() []string { return []string{r.name} }

func (r *writableStoreRuntime) WriteData(storeName, source string, entry *datastores.DataEntry) error {
	if err := r.guard(storeName); err != nil {
		return err
	}
	return r.store.Write(source, entry)
}

func (r *writableStoreRuntime) WriteBatchData(storeName, source string, entries []*datastores.DataEntry) error {
	if err := r.guard(storeName); err != nil {
		return err
	}
	return r.store.WriteBatch(source, entries)
}

func (r *writableStoreRuntime) DeleteData(storeName, source string, key *anypb.Any) error {
	if err := r.guard(storeName); err != nil {
		return err
	}
	return r.store.Delete(source, key)
}

func (r *writableStoreRuntime) ClearSource(storeName, source string) error {
	if err := r.guard(storeName); err != nil {
		return err
	}
	return r.store.Clear(source)
}

func (r *writableStoreRuntime) ListSources(storeName string) ([]string, error) {
	if err := r.guard(storeName); err != nil {
		return nil, err
	}
	return r.store.ListSources()
}
