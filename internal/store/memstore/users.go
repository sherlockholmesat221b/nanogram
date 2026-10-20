// File: internal/store/memstore/users.go

package memstore

import (
	"bytes"
	"context"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

func (m *MemStore) ReserveUsername(
	ctx context.Context,
	username string,
	userID []byte,
	now, until time.Time,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.usersByName[username]; ok {
		return store.ErrTaken
	}

	if r, ok := m.reservations[username]; ok && r.expires.After(now) {
		return store.ErrTaken
	}

	m.reservations[username] = reservation{
		userID:  clone(userID),
		expires: until,
	}

	return nil
}

func (m *MemStore) CreateUser(
	ctx context.Context,
	u store.User,
	records []store.OpaqueRecord,
	blobs []store.Blob,
	keys []store.PublicKey,
	now time.Time,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.usersByName[u.Username]; ok {
		return store.ErrTaken
	}

	r, ok := m.reservations[u.Username]
	if !ok || !r.expires.After(now) || !bytes.Equal(r.userID, u.ID) {
		return store.ErrConflict
	}

	id := string(u.ID)
	if _, exists := m.usersByID[id]; exists {
		return store.ErrConflict
	}

	// Validate all input before mutating any stored state
	seenOpaque := make(map[opaqueKey]struct{}, len(records))
	for _, rec := range records {
		if !bytes.Equal(rec.UserID, u.ID) ||
			rec.Pending ||
			(rec.Kind != "password" && rec.Kind != "recovery") {
			return store.ErrConflict
		}

		key := opaqueKey{
			userID:  id,
			kind:    rec.Kind,
			pending: false,
		}

		if _, exists := m.opaque[key]; exists {
			return store.ErrConflict
		}
		if _, exists := seenOpaque[key]; exists {
			return store.ErrConflict
		}
		seenOpaque[key] = struct{}{}
	}

	seenBlobs := make(map[blobKey]struct{}, len(blobs))
	for _, b := range blobs {
		if !bytes.Equal(b.UserID, u.ID) || b.Pending {
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
		if _, exists := seenBlobs[key]; exists {
			return store.ErrConflict
		}
		seenBlobs[key] = struct{}{}
	}

	seenKeys := make(map[pubKeyKey]struct{}, len(keys))
	for _, pk := range keys {
		if !bytes.Equal(pk.UserID, u.ID) ||
			(pk.Kind != "mlkem" && pk.Kind != "sign") ||
			pk.Version != 1 ||
			len(pk.Key) < 1 ||
			len(pk.Key) > 2048 {
			return store.ErrConflict
		}

		key := pubKeyKey{
			userID:  id,
			kind:    pk.Kind,
			version: pk.Version,
		}

		if _, exists := m.pubKeys[key]; exists {
			return store.ErrConflict
		}
		if _, exists := seenKeys[key]; exists {
			return store.ErrConflict
		}
		seenKeys[key] = struct{}{}
	}

	cu := cloneUser(u)
	m.usersByName[u.Username] = cu
	m.usersByID[id] = cu

	for _, rec := range records {
		key := opaqueKey{
			userID:  id,
			kind:    rec.Kind,
			pending: false,
		}
		m.opaque[key] = cloneOpaque(rec)
	}

	for _, b := range blobs {
		key := blobKey{
			userID:  id,
			kind:    b.Kind,
			version: b.Version,
		}
		m.blobs[key] = cloneBlob(b)
	}

	for _, pk := range keys {
		key := pubKeyKey{
			userID:  id,
			kind:    pk.Kind,
			version: pk.Version,
		}
		cp := clonePublicKey(pk)
		cp.CreatedAt = now
		m.pubKeys[key] = cp
	}

	delete(m.reservations, u.Username)
	return nil
}

func (m *MemStore) UserByUsername(
	ctx context.Context,
	username string,
) (store.User, error) {
	if err := checkContext(ctx); err != nil {
		return store.User{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	u, ok := m.usersByName[username]
	if !ok {
		return store.User{}, store.ErrNotFound
	}

	return cloneUser(u), nil
}
