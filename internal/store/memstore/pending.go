// File: internal/store/memstore/pending.go

package memstore

import (
	"context"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

// PendingOpaqueRecord returns the record of a password change that has begun
// and has not expired.
func (m *MemStore) PendingOpaqueRecord(
	ctx context.Context,
	userID []byte,
	kind string,
	now time.Time,
) (store.OpaqueRecord, error) {
	if err := checkContext(ctx); err != nil {
		return store.OpaqueRecord{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := string(userID)

	rec, ok := m.opaque[opaqueKey{userID: id, kind: kind, pending: true}]
	until, hasExpiry := m.expiries[id]

	if !ok || !hasExpiry || !until.After(now) {
		return store.OpaqueRecord{}, store.ErrNotFound
	}

	return cloneOpaque(rec), nil
}
