// File: internal/store/memstore/publickeys_test.go

package memstore

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

func TestPutPublicKey(t *testing.T) {
	m := New()
	uid := id(1)
	createUser(t, m, "alice", uid)

	if err := m.PutPublicKey(ctx, uid, "sign", 2, []byte("key2"), t0); err != nil {
		t.Fatalf("put public key: %v", err)
	}

	if err := m.PutPublicKey(ctx, uid, "sign", 2, []byte("duplicate"), t0); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("duplicate public key error = %v, want ErrConflict", err)
	}
}

func TestPublicKeys(t *testing.T) {
	m := New()
	uid := id(1)
	createUser(t, m, "alice", uid)

	if _, err := m.PublicKeys(ctx, uid, "sign"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing public keys error = %v", err)
	}

	if err := m.PutPublicKey(ctx, uid, "sign", 3, []byte("key3"), t0); err != nil {
		t.Fatal(err)
	}
	if err := m.PutPublicKey(ctx, uid, "sign", 1, []byte("key1"), t0); err != nil {
		t.Fatal(err)
	}
	if err := m.PutPublicKey(ctx, uid, "sign", 2, []byte("key2"), t0); err != nil {
		t.Fatal(err)
	}

	pks, err := m.PublicKeys(ctx, uid, "sign")
	if err != nil {
		t.Fatal(err)
	}

	if len(pks) != 3 {
		t.Fatalf("got %d public keys, want 3", len(pks))
	}

	for i, wantVersion := range []uint32{1, 2, 3} {
		if pks[i].Version != wantVersion {
			t.Fatalf("public key at index %d has version %d, want %d", i, pks[i].Version, wantVersion)
		}
	}

	if string(pks[0].Key) != "key1" ||
		string(pks[1].Key) != "key2" ||
		string(pks[2].Key) != "key3" {
		t.Fatalf("unexpected public key contents: %+v", pks)
	}
}

func TestPutPublicKeyValidationAndCreatedAt(t *testing.T) {
	m := New()
	uid := id(1)
	createUser(t, m, "alice", uid)

	now := t0.Add(10 * time.Minute)

	for _, kind := range []string{"signing", "", "unknown"} {
		if err := m.PutPublicKey(ctx, uid, kind, 1, []byte("key"), now); !errors.Is(err, store.ErrConflict) {
			t.Fatalf("kind %q: error = %v, want ErrConflict", kind, err)
		}
	}

	if err := m.PutPublicKey(ctx, uid, "mlkem", 1, []byte("kem-key"), now); err != nil {
		t.Fatal(err)
	}
	if err := m.PutPublicKey(ctx, uid, "sign", 1, []byte("sign-key"), now); err != nil {
		t.Fatal(err)
	}

	for _, kind := range []string{"mlkem", "sign"} {
		keys, err := m.PublicKeys(ctx, uid, kind)
		if err != nil {
			t.Fatal(err)
		}
		if len(keys) != 1 {
			t.Fatalf("kind %q: got %d keys, want 1", kind, len(keys))
		}
		if !keys[0].CreatedAt.Equal(now) {
			t.Fatalf("kind %q: CreatedAt = %v, want %v", kind, keys[0].CreatedAt, now)
		}
	}

	if err := m.PutPublicKey(ctx, id(9), "invalid", 1, []byte("key"), now); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("invalid kind for missing user = %v, want ErrConflict", err)
	}
}

func TestCreateUserPublicKeysAtomicValidation(t *testing.T) {
	tests := []struct {
		name string
		keys []store.PublicKey
	}{
		{
			name: "wrong user ID",
			keys: []store.PublicKey{{
				UserID: id(9), Kind: "sign", Version: 1, Key: []byte("key"),
			}},
		},
		{
			name: "invalid kind",
			keys: []store.PublicKey{{
				Kind: "signing", Version: 1, Key: []byte("key"),
			}},
		},
		{
			name: "wrong version",
			keys: []store.PublicKey{{
				Kind: "sign", Version: 2, Key: []byte("key"),
			}},
		},
		{
			name: "empty key",
			keys: []store.PublicKey{{
				Kind: "sign", Version: 1,
			}},
		},
		{
			name: "oversized key",
			keys: []store.PublicKey{{
				Kind: "sign", Version: 1, Key: bytes.Repeat([]byte{1}, 2049),
			}},
		},
		{
			name: "duplicate keys",
			keys: []store.PublicKey{
				{Kind: "sign", Version: 1, Key: []byte("key1")},
				{Kind: "sign", Version: 1, Key: []byte("key2")},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New()
			uid := id(1)
			username := "alice"

			if err := m.ReserveUsername(ctx, username, uid, t0, t0.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}

			for i := range tt.keys {
				if tt.keys[i].UserID == nil {
					tt.keys[i].UserID = clone(uid)
				}
			}

			err := m.CreateUser(
				ctx,
				store.User{ID: uid, Username: username, CreatedAt: t0},
				nil,
				nil,
				tt.keys,
				t0,
			)
			if !errors.Is(err, store.ErrConflict) {
				t.Fatalf("CreateUser error = %v, want ErrConflict", err)
			}

			if _, err := m.UserByUsername(ctx, username); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("user was partially created: %v", err)
			}

			if len(m.pubKeys) != 0 {
				t.Fatalf("public keys were partially stored: %d", len(m.pubKeys))
			}

			if _, ok := m.reservations[username]; !ok {
				t.Fatal("reservation was removed after failed CreateUser")
			}
		})
	}
}

func TestCreateUserStoresPublicKeys(t *testing.T) {
	m := New()
	uid := id(1)
	username := "alice"

	if err := m.ReserveUsername(ctx, username, uid, t0, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	now := t0.Add(5 * time.Minute)
	keys := []store.PublicKey{
		{UserID: clone(uid), Kind: "mlkem", Version: 1, Key: []byte("kem-key")},
		{UserID: clone(uid), Kind: "sign", Version: 1, Key: []byte("sign-key")},
	}

	if err := m.CreateUser(
		ctx,
		store.User{ID: uid, Username: username, CreatedAt: t0},
		nil,
		nil,
		keys,
		now,
	); err != nil {
		t.Fatal(err)
	}

	for _, kind := range []string{"mlkem", "sign"} {
		got, err := m.PublicKeys(ctx, uid, kind)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Version != 1 {
			t.Fatalf("kind %q: unexpected keys: %+v", kind, got)
		}
		if !got[0].CreatedAt.Equal(now) {
			t.Fatalf("kind %q: CreatedAt = %v, want %v", kind, got[0].CreatedAt, now)
		}
	}
}
