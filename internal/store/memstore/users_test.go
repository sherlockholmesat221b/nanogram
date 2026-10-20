// File: internal/store/memstore/users_test.go

package memstore

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

func TestReserveUsernameAndConcurrentWinner(t *testing.T) {
	m := New()

	if err := m.ReserveUsername(ctx, "taken", id(1), t0, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := m.ReserveUsername(ctx, "taken", id(2), t0, t0.Add(time.Hour)); !errors.Is(err, store.ErrTaken) {
		t.Fatalf("second reservation error = %v", err)
	}

	if err := m.ReserveUsername(ctx, "taken", id(2), t0.Add(2*time.Hour), t0.Add(3*time.Hour)); err != nil {
		t.Fatalf("expired reservation should be replaceable: %v", err)
	}

	m2 := New()
	var wg sync.WaitGroup
	results := make(chan error, 2)

	for i := byte(1); i <= 2; i++ {
		wg.Add(1)
		go func(n byte) {
			defer wg.Done()
			results <- m2.ReserveUsername(ctx, "same", id(n), t0, t0.Add(time.Hour))
		}(i)
	}

	wg.Wait()
	close(results)

	wins, losses := 0, 0
	for err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, store.ErrTaken):
			losses++
		default:
			t.Fatalf("unexpected reservation error: %v", err)
		}
	}

	if wins != 1 || losses != 1 {
		t.Fatalf("wins=%d losses=%d, want 1 each", wins, losses)
	}
}

func TestCreateUserAndUserByUsername(t *testing.T) {
	m := New()
	uid := id(1)

	if err := m.CreateUser(ctx, store.User{ID: uid, Username: "alice"}, nil, nil, nil, t0); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("without reservation: %v", err)
	}

	createUser(t, m, "alice", uid)

	if err := m.CreateUser(ctx, store.User{ID: id(2), Username: "alice"}, nil, nil, nil, t0); !errors.Is(err, store.ErrTaken) {
		t.Fatalf("duplicate username: %v", err)
	}

	if _, err := m.UserByUsername(ctx, "missing"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}

	u, err := m.UserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "alice" || !bytes.Equal(u.ID, uid) {
		t.Fatalf("unexpected user: %+v", u)
	}

	if err := m.ReserveUsername(ctx, "alice", id(2), t0, t0.Add(time.Hour)); !errors.Is(err, store.ErrTaken) {
		t.Fatalf("existing username reservation: %v", err)
	}

	if err := m.ReserveUsername(ctx, "bob", id(2), t0, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := m.CreateUser(ctx, store.User{ID: id(3), Username: "bob"}, nil, nil, nil, t0); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("reservation owner mismatch: %v", err)
	}
}

func TestMutationsForMissingUser(t *testing.T) {
	m := New()
	uid := id(9)

	blob := store.Blob{
		UserID:  uid,
		Kind:    store.BlobKindMEK,
		Version: 1,
		Data:    []byte("mek1"),
	}
	if err := m.AppendBlob(ctx, blob); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("append blob for missing user error = %v, want ErrNotFound", err)
	}

	if err := m.PutPublicKey(ctx, uid, "sign", 1, []byte("key1"), t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("put public key for missing user error = %v, want ErrNotFound", err)
	}

	if err := m.DeleteRecovery(ctx, uid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete recovery for missing user error = %v, want ErrNotFound", err)
	}
}
