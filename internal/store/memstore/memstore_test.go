// File: internal/store/memstore/memstore_test.go

package memstore

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
)

func id(n byte) []byte {
	return bytes.Repeat([]byte{n}, 16)
}

func hash(n byte) [32]byte {
	var h [32]byte
	for i := range h {
		h[i] = n
	}
	return h
}

func createUser(t *testing.T, m *MemStore, username string, uid []byte) {
	t.Helper()

	if err := m.ReserveUsername(ctx, username, uid, t0, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	u := store.User{
		ID:        uid,
		Username:  username,
		CreatedAt: t0,
	}

	r := store.OpaqueRecord{
		UserID: uid,
		Kind:   "password",
		Record: []byte("record"),
	}

	b := store.Blob{
		UserID:  uid,
		Kind:    store.BlobKindKEK,
		Version: 1,
		Data:    []byte("kek1"),
	}

	if err := m.CreateUser(ctx, u, []store.OpaqueRecord{r}, []store.Blob{b}, nil, t0); err != nil {
		t.Fatal(err)
	}
}

func TestCopiesInputSlices(t *testing.T) {
	m := New()
	uid := id(1)
	createUser(t, m, "alice", uid)

	// Mutating the caller's original ID must not change stored user data
	uid[0] = 88

	got, err := m.UserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID[0] != 1 {
		t.Fatalf("stored user ID changed to %d", got.ID[0])
	}
}

func TestContextCancellation(t *testing.T) {
	m := New()
	c, cancel := context.WithCancel(context.Background())
	cancel()

	if err := m.DeleteExpired(c, t0); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled context error = %v", err)
	}
}
