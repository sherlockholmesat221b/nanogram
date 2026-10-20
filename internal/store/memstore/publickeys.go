// File: internal/store/memstore/publickeys.go

package memstore

import (
	"context"
	"sort"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

func (m *MemStore) PutPublicKey(
	ctx context.Context,
	userID []byte,
	kind string,
	version uint32,
	key []byte,
	now time.Time,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	if kind != "mlkem" && kind != "sign" {
		return store.ErrConflict
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := string(userID)
	if _, exists := m.usersByID[id]; !exists {
		return store.ErrNotFound
	}

	pkKey := pubKeyKey{
		userID:  id,
		kind:    kind,
		version: version,
	}

	if _, exists := m.pubKeys[pkKey]; exists {
		return store.ErrConflict
	}

	m.pubKeys[pkKey] = store.PublicKey{
		UserID:    clone(userID),
		Kind:      kind,
		Version:   version,
		Key:       clone(key),
		CreatedAt: now,
	}
	return nil
}

func (m *MemStore) PublicKeys(
	ctx context.Context,
	userID []byte,
	kind string,
) ([]store.PublicKey, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := string(userID)
	var list []store.PublicKey

	for pkKey, pk := range m.pubKeys {
		if pkKey.userID == id && pkKey.kind == kind {
			list = append(list, clonePublicKey(pk))
		}
	}

	if len(list) == 0 {
		return nil, store.ErrNotFound
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].Version < list[j].Version
	})

	return list, nil
}
