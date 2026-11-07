// File: internal/store/memstore/recovery.go

package memstore

import (
	"bytes"
	"context"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

func (m *MemStore) ReplaceRecovery(
	ctx context.Context,
	userID []byte,
	expectedVersion uint64,
	rec store.OpaqueRecord,
	blob store.Blob,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := string(userID)
	if _, exists := m.usersByID[id]; !exists {
		return store.ErrNotFound
	}

	if rec.Pending || blob.Pending || rec.Kind != "recovery" || blob.Kind != store.BlobKindRecovery {
		return store.ErrConflict
	}
	if !bytes.Equal(rec.UserID, userID) || !bytes.Equal(blob.UserID, userID) {
		return store.ErrConflict
	}

	var currentVersion uint64
	hasAny := false
	for key, existing := range m.blobs {
		if key.userID == id && key.kind == store.BlobKindRecovery && !existing.Pending {
			hasAny = true
			if existing.Version > currentVersion {
				currentVersion = existing.Version
			}
		}
	}
	if !hasAny {
		currentVersion = 0
	}

	if currentVersion != expectedVersion {
		return store.ErrConflict
	}
	if expectedVersion == ^uint64(0) || blob.Version != expectedVersion+1 {
		return store.ErrConflict
	}

	oldOpaqueKey := opaqueKey{
		userID:  id,
		kind:    "recovery",
		pending: false,
	}

	newBlobKey := blobKey{
		userID:  id,
		kind:    blob.Kind,
		version: blob.Version,
	}
	if _, exists := m.blobs[newBlobKey]; exists {
		return store.ErrConflict
	}

	delete(m.opaque, oldOpaqueKey)
	m.opaque[oldOpaqueKey] = cloneOpaque(rec)
	m.blobs[newBlobKey] = cloneBlob(blob)
	return nil
}

func (m *MemStore) DeleteRecovery(
	ctx context.Context,
	userID []byte,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := string(userID)
	oldOpaqueKey := opaqueKey{
		userID:  id,
		kind:    "recovery",
		pending: false,
	}

	if _, ok := m.opaque[oldOpaqueKey]; !ok {
		return store.ErrNotFound
	}

	delete(m.opaque, oldOpaqueKey)
	for key := range m.blobs {
		if key.userID == id && key.kind == store.BlobKindRecovery {
			delete(m.blobs, key)
		}
	}

	return nil
}
