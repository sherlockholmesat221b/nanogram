// File: internal/store/memstore/loginstates.go

package memstore

import (
	"context"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

func (m *MemStore) PutLoginState(
	ctx context.Context,
	ls store.LoginState,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.loginStates[ls.IDHash]; ok {
		return store.ErrConflict
	}

	m.loginStates[ls.IDHash] = cloneLoginState(ls)
	return nil
}

func (m *MemStore) TakeLoginState(
	ctx context.Context,
	idHash [32]byte,
	now time.Time,
) (store.LoginState, error) {
	if err := checkContext(ctx); err != nil {
		return store.LoginState{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	ls, ok := m.loginStates[idHash]
	if !ok {
		return store.LoginState{}, store.ErrNotFound
	}

	// Delete before returning, including when the state has expired
	delete(m.loginStates, idHash)

	if !ls.ExpiresAt.After(now) {
		return store.LoginState{}, store.ErrNotFound
	}

	return cloneLoginState(ls), nil
}
