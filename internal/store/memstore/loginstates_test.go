// File: internal/store/memstore/loginstates_test.go

package memstore

import (
	"errors"
	"testing"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

func TestLoginStateSingleUseAndExpiry(t *testing.T) {
	m := New()
	ls := store.LoginState{
		IDHash:    hash(1),
		Username:  "alice",
		Kind:      "password",
		State:     []byte("state"),
		ExpiresAt: t0.Add(time.Hour),
	}

	if err := m.PutLoginState(ctx, ls); err != nil {
		t.Fatal(err)
	}
	if err := m.PutLoginState(ctx, ls); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate login state: %v", err)
	}

	got, err := m.TakeLoginState(ctx, ls.IDHash, t0)
	if err != nil || string(got.State) != "state" {
		t.Fatalf("take=%+v err=%v", got, err)
	}

	if _, err := m.TakeLoginState(ctx, ls.IDHash, t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second take: %v", err)
	}
	if _, err := m.TakeLoginState(ctx, hash(9), t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing login state: %v", err)
	}

	expired := ls
	expired.IDHash = hash(2)
	expired.ExpiresAt = t0

	if err := m.PutLoginState(ctx, expired); err != nil {
		t.Fatal(err)
	}
	if _, err := m.TakeLoginState(ctx, expired.IDHash, t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired state: %v", err)
	}
}
