// File: internal/store/memstore/records.go

package memstore

import (
	"context"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

func (m *MemStore) CurrentOpaqueRecord(
	ctx context.Context,
	userID []byte,
	kind string,
) (store.OpaqueRecord, error) {
	if err := checkContext(ctx); err != nil {
		return store.OpaqueRecord{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := opaqueKey{
		userID:  string(userID),
		kind:    kind,
		pending: false,
	}

	r, ok := m.opaque[key]
	if !ok {
		return store.OpaqueRecord{}, store.ErrNotFound
	}

	return cloneOpaque(r), nil
}

func (m *MemStore) CurrentBlob(
	ctx context.Context,
	userID []byte,
	kind byte,
) (store.Blob, error) {
	if err := checkContext(ctx); err != nil {
		return store.Blob{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var best store.Blob
	found := false

	for key, b := range m.blobs {
		if key.userID != string(userID) ||
			key.kind != kind ||
			b.Pending {
			continue
		}

		if !found || b.Version > best.Version {
			best = b
			found = true
		}
	}

	if !found {
		return store.Blob{}, store.ErrNotFound
	}

	return cloneBlob(best), nil
}

func (m *MemStore) AppendBlob(
	ctx context.Context,
	b store.Blob,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := string(b.UserID)
	if _, exists := m.usersByID[id]; !exists {
		return store.ErrNotFound
	}

	if b.Pending {
		return store.ErrConflict
	}

	if b.Kind == store.BlobKindKEK ||
		b.Kind == store.BlobKindRecovery {
		return store.ErrConflict
	}

	var maxVer uint64
	hasAny := false

	for key, existing := range m.blobs {
		if key.userID == id && key.kind == b.Kind && !existing.Pending {
			hasAny = true
			if existing.Version > maxVer {
				maxVer = existing.Version
			}
		}
	}

	expectedVersion := uint64(1)
	if hasAny {
		expectedVersion = maxVer + 1
	}

	if b.Version != expectedVersion {
		return store.ErrConflict
	}

	key := blobKey{
		userID:  id,
		kind:    b.Kind,
		version: b.Version,
	}
	if _, exists := m.blobs[key]; exists {
		return store.ErrConflict
	}

	m.blobs[key] = cloneBlob(b)
	return nil
}
