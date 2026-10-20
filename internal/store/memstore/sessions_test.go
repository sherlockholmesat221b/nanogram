// File: internal/store/memstore/sessions_test.go

package memstore

import (
	"errors"
	"testing"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

func TestSessionsCountersDeletionAndExpiry(t *testing.T) {
	m := New()
	s := store.Session{
		IDHash:    hash(1),
		UserID:    id(1),
		Scope:     "full",
		Key:       []byte("key"),
		ExpiresAt: t0.Add(time.Hour),
	}

	if err := m.PutSession(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := m.PutSession(ctx, s); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate session: %v", err)
	}

	if _, err := m.SessionByIDHash(ctx, hash(2), t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing session: %v", err)
	}

	got, err := m.SessionByIDHash(ctx, s.IDHash, t0)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Key) != "key" {
		t.Fatalf("key=%q", got.Key)
	}

	if err := m.AdvanceCounter(ctx, hash(2), 1, time.Time{}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("counter for missing session: %v", err)
	}
	if err := m.AdvanceCounter(ctx, s.IDHash, 0, time.Time{}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("non-increasing counter: %v", err)
	}
	if err := m.AdvanceCounter(ctx, s.IDHash, 4, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := m.AdvanceCounter(ctx, s.IDHash, 3, time.Time{}); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("counter rollback: %v", err)
	}

	got, err = m.SessionByIDHash(ctx, s.IDHash, t0)
	if err != nil || got.LastCounter != 4 {
		t.Fatalf("counter=%d err=%v", got.LastCounter, err)
	}

	if err := m.DeleteSessionsForUser(ctx, id(9)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SessionByIDHash(ctx, s.IDHash, t0); err != nil {
		t.Fatalf("unrelated deletion removed session: %v", err)
	}

	if err := m.DeleteSessionsForUser(ctx, s.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SessionByIDHash(ctx, s.IDHash, t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("session after user deletion: %v", err)
	}

	expired := store.Session{
		IDHash:    hash(3),
		UserID:    id(2),
		Scope:     "full",
		ExpiresAt: t0,
	}
	if err := m.PutSession(ctx, expired); err != nil {
		t.Fatal(err)
	}
	if _, err := m.SessionByIDHash(ctx, hash(3), t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired session: %v", err)
	}
}

func TestPutSessionScopeValidation(t *testing.T) {
	m := New()

	for _, scope := range []string{"", "invalid", "FULL"} {
		s := store.Session{
			IDHash:    hash(byte(len(scope) + 1)),
			UserID:    id(1),
			Scope:     scope,
			ExpiresAt: t0.Add(time.Hour),
		}

		if err := m.PutSession(ctx, s); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("scope %q: error = %v, want ErrConflict", scope, err)
		}
	}

	for i, scope := range []string{"full", "recovery"} {
		s := store.Session{
			IDHash:    hash(byte(20 + i)),
			UserID:    id(1),
			Scope:     scope,
			ExpiresAt: t0.Add(time.Hour),
		}

		if err := m.PutSession(ctx, s); err != nil {
			t.Fatalf("scope %q: %v", scope, err)
		}

		got, err := m.SessionByIDHash(ctx, s.IDHash, t0)
		if err != nil {
			t.Fatal(err)
		}
		if got.Scope != scope {
			t.Fatalf("stored scope = %q, want %q", got.Scope, scope)
		}
	}
}

func TestAdvanceCounterExtendsExpiry(t *testing.T) {
	m := New()
	s := store.Session{
		IDHash:       hash(1),
		UserID:       id(1),
		Scope:        "full",
		Key:          []byte("key"),
		ExpiresAt:    t0.Add(30 * time.Minute),
		MaxExpiresAt: t0.Add(time.Hour),
	}
	if err := m.PutSession(ctx, s); err != nil {
		t.Fatal(err)
	}

	expiry := func(idHash [32]byte) time.Time {
		got, err := m.SessionByIDHash(ctx, idHash, t0)
		if err != nil {
			t.Fatal(err)
		}
		return got.ExpiresAt
	}

	// The expiry moves forward.
	if err := m.AdvanceCounter(ctx, s.IDHash, 1, t0.Add(45*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := expiry(s.IDHash); !got.Equal(t0.Add(45 * time.Minute)) {
		t.Fatalf("expiry after extension = %v", got)
	}

	// It never moves back.
	if err := m.AdvanceCounter(ctx, s.IDHash, 2, t0.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := expiry(s.IDHash); !got.Equal(t0.Add(45 * time.Minute)) {
		t.Fatalf("expiry moved back to %v", got)
	}

	// A zero value leaves it alone.
	if err := m.AdvanceCounter(ctx, s.IDHash, 3, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if got := expiry(s.IDHash); !got.Equal(t0.Add(45 * time.Minute)) {
		t.Fatalf("zero expiry changed it to %v", got)
	}

	// It stops at the absolute limit.
	if err := m.AdvanceCounter(ctx, s.IDHash, 4, t0.Add(3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := expiry(s.IDHash); !got.Equal(t0.Add(time.Hour)) {
		t.Fatalf("expiry passed the limit: %v", got)
	}

	// Without a limit it goes as far as asked, but a refused counter
	// extends nothing.
	free := store.Session{
		IDHash:      hash(2),
		UserID:      id(1),
		Scope:       "full",
		Key:         []byte("key"),
		LastCounter: 5,
		ExpiresAt:   t0.Add(10 * time.Minute),
	}
	if err := m.PutSession(ctx, free); err != nil {
		t.Fatal(err)
	}
	if err := m.AdvanceCounter(ctx, free.IDHash, 5, t0.Add(2*time.Hour)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("repeated counter: %v", err)
	}
	if got := expiry(free.IDHash); !got.Equal(t0.Add(10 * time.Minute)) {
		t.Fatalf("a refused counter extended the session to %v", got)
	}
	if err := m.AdvanceCounter(ctx, free.IDHash, 6, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := expiry(free.IDHash); !got.Equal(t0.Add(2 * time.Hour)) {
		t.Fatalf("expiry without a limit = %v", got)
	}
}
