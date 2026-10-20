// File: internal/store/memstore/expiry.go

package memstore

import (
	"context"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

func (m *MemStore) DeleteExpired(
	ctx context.Context,
	now time.Time,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for username, r := range m.reservations {
		if !r.expires.After(now) {
			delete(m.reservations, username)
		}
	}

	for id, until := range m.expiries {
		if !until.After(now) {
			delete(m.expiries, id)
			delete(m.opaque, opaqueKey{userID: id, kind: "password", pending: true})
			for bKey, b := range m.blobs {
				if bKey.userID == id && bKey.kind == store.BlobKindKEK && b.Pending {
					delete(m.blobs, bKey)
				}
			}
		}
	}

	for id, s := range m.loginStates {
		if !s.ExpiresAt.After(now) {
			delete(m.loginStates, id)
		}
	}

	for id, s := range m.sessions {
		if !s.ExpiresAt.After(now) {
			delete(m.sessions, id)
		}
	}

	return nil
}
