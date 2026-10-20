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

	var maxVer uint64
	hasAny := false
	for key, existing := range m.blobs {
		if key.userID == id && key.kind == store.BlobKindRecovery && !existing.Pending {
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

	if blob.Version != expectedVersion {
		return store.ErrConflict
	}

	// Delete old current recovery opaque record if any
	oldOpaqueKey := opaqueKey{
		userID:  id,
		kind:    "recovery",
		pending: false,
	}
	delete(m.opaque, oldOpaqueKey)

	newBlobKey := blobKey{
		userID:  id,
		kind:    blob.Kind,
		version: blob.Version,
	}
	if _, exists := m.blobs[newBlobKey]; exists {
		return store.ErrConflict
	}

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
