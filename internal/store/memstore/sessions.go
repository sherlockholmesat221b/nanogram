// File: internal/store/memstore/sessions.go

package memstore

import (
	"bytes"
	"context"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

func (m *MemStore) PutSession(ctx context.Context, s store.Session) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	if s.Scope != "full" && s.Scope != "recovery" {
		return store.ErrConflict
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.sessions[s.IDHash]; ok {
		return store.ErrConflict
	}

	m.sessions[s.IDHash] = cloneSession(s)
	return nil
}

func (m *MemStore) SessionByIDHash(
	ctx context.Context,
	idHash [32]byte,
	now time.Time,
) (store.Session, error) {
	if err := checkContext(ctx); err != nil {
		return store.Session{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[idHash]
	if !ok || !s.ExpiresAt.After(now) {
		return store.Session{}, store.ErrNotFound
	}

	return cloneSession(s), nil
}

func (m *MemStore) AdvanceCounter(
	ctx context.Context,
	idHash [32]byte,
	counter uint64,
	expiresAt time.Time,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[idHash]
	if !ok {
		return store.ErrNotFound
	}

	if counter <= s.LastCounter {
		return store.ErrConflict
	}

	s.LastCounter = counter

	// The expiry only moves forward, and never past the absolute limit.
	if !s.MaxExpiresAt.IsZero() && expiresAt.After(s.MaxExpiresAt) {
		expiresAt = s.MaxExpiresAt
	}
	if expiresAt.After(s.ExpiresAt) {
		s.ExpiresAt = expiresAt
	}

	m.sessions[idHash] = s
	return nil
}

func (m *MemStore) DeleteSessionsForUser(
	ctx context.Context,
	userID []byte,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for id, s := range m.sessions {
		if bytes.Equal(s.UserID, userID) {
			delete(m.sessions, id)
		}
	}

	return nil
}
