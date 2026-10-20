// File: internal/store/memstore/passwordchange.go

package memstore

import (
	"bytes"
	"context"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

func (m *MemStore) hasPendingPasswordChange(
	userID []byte,
	now time.Time,
) bool {
	id := string(userID)

	if _, ok := m.opaque[opaqueKey{
		userID:  id,
		kind:    "password",
		pending: true,
	}]; ok {
		until, exists := m.expiries[id]
		if exists && until.After(now) {
			return true
		}
	}

	for key, b := range m.blobs {
		if key.userID != id ||
			key.kind != store.BlobKindKEK ||
			!b.Pending {
			continue
		}

		until, exists := m.expiries[id]
		if exists && until.After(now) {
			return true
		}
	}

	return false
}

func (m *MemStore) BeginPasswordChange(
	ctx context.Context,
	userID []byte,
	expectedKEKVersion uint64,
	rec store.OpaqueRecord,
	kek store.Blob,
	now, until time.Time,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.hasPendingPasswordChange(userID, now) {
		return store.ErrConflict
	}

	id := string(userID)

	delete(m.opaque, opaqueKey{
		userID:  id,
		kind:    "password",
		pending: true,
	})
	for key, b := range m.blobs {
		if key.userID == id &&
			key.kind == store.BlobKindKEK &&
			b.Pending {
			delete(m.blobs, key)
		}
	}
	delete(m.expiries, id)

	var current store.Blob
	found := false

	for key, b := range m.blobs {
		if key.userID != id ||
			key.kind != store.BlobKindKEK ||
			b.Pending {
			continue
		}

		if !found || b.Version > current.Version {
			current = b
			found = true
		}
	}

	if !found || current.Version != expectedKEKVersion {
		return store.ErrConflict
	}

	if expectedKEKVersion == ^uint64(0) ||
		kek.Version != expectedKEKVersion+1 {
		return store.ErrConflict
	}

	if !bytes.Equal(rec.UserID, userID) ||
		rec.Kind != "password" ||
		!rec.Pending ||
		!bytes.Equal(kek.UserID, userID) ||
		kek.Kind != store.BlobKindKEK ||
		!kek.Pending {
		return store.ErrConflict
	}

	opaqueKey := opaqueKey{
		userID:  id,
		kind:    "password",
		pending: true,
	}
	newBlobKey := blobKey{
		userID:  id,
		kind:    kek.Kind,
		version: kek.Version,
	}

	if _, exists := m.opaque[opaqueKey]; exists {
		return store.ErrConflict
	}
	if _, exists := m.blobs[newBlobKey]; exists {
		return store.ErrConflict
	}

	m.opaque[opaqueKey] = cloneOpaque(rec)
	m.blobs[newBlobKey] = cloneBlob(kek)
	m.expiries[id] = until

	return nil
}

func (m *MemStore) CommitPasswordChange(
	ctx context.Context,
	userID []byte,
	now time.Time,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := string(userID)
	pendingOpaqueKey := opaqueKey{
		userID:  id,
		kind:    "password",
		pending: true,
	}

	pendingRec, foundRecord := m.opaque[pendingOpaqueKey]

	var pendingBlobKey blobKey
	foundBlob := false

	for key, b := range m.blobs {
		if key.userID == id &&
			key.kind == store.BlobKindKEK &&
			b.Pending {
			pendingBlobKey = key
			foundBlob = true
			break
		}
	}

	until, foundExpiry := m.expiries[id]
	if !foundRecord || !foundBlob || !foundExpiry || !until.After(now) {
		return store.ErrNotFound
	}

	delete(m.opaque, pendingOpaqueKey)
	pendingRec.Pending = false
	m.opaque[opaqueKey{
		userID:  id,
		kind:    "password",
		pending: false,
	}] = cloneOpaque(pendingRec)

	pendingBlob := m.blobs[pendingBlobKey]
	pendingBlob.Pending = false
	m.blobs[pendingBlobKey] = cloneBlob(pendingBlob)
	delete(m.expiries, id)

	return nil
}

func (m *MemStore) AbortPasswordChange(
	ctx context.Context,
	userID []byte,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := string(userID)
	pendingOpaqueKey := opaqueKey{
		userID:  id,
		kind:    "password",
		pending: true,
	}

	found := false

	if _, ok := m.opaque[pendingOpaqueKey]; ok {
		delete(m.opaque, pendingOpaqueKey)
		found = true
	}

	for key, b := range m.blobs {
		if key.userID == id &&
			key.kind == store.BlobKindKEK &&
			b.Pending {
			delete(m.blobs, key)
			found = true
		}
	}

	if !found {
		return store.ErrNotFound
	}

	delete(m.expiries, id)
	return nil
}
