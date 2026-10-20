// File: internal/store/memstore/expiry_test.go

package memstore

import (
	"errors"
	"testing"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

func TestDeleteExpiredAndSliceCopies(t *testing.T) {
	m := New()
	uid := id(1)
	createUser(t, m, "alice", uid)

	user, err := m.UserByUsername(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	user.ID[0] = 99

	user, err = m.UserByUsername(ctx, "alice")
	if err != nil || user.ID[0] != 1 {
		t.Fatalf("user ID mutated through returned slice: %v", err)
	}

	record, err := m.CurrentOpaqueRecord(ctx, uid, "password")
	if err != nil {
		t.Fatal(err)
	}
	record.Record[0] = 'X'

	record, err = m.CurrentOpaqueRecord(ctx, uid, "password")
	if err != nil || string(record.Record) != "record" {
		t.Fatalf("record slice alias: %+v %v", record, err)
	}

	blob, err := m.CurrentBlob(ctx, uid, store.BlobKindKEK)
	if err != nil {
		t.Fatal(err)
	}
	blob.Data[0] = 'X'

	blob, err = m.CurrentBlob(ctx, uid, store.BlobKindKEK)
	if err != nil || string(blob.Data) != "kek1" {
		t.Fatalf("blob slice alias: %+v %v", blob, err)
	}

	state := []byte("mutable")
	ls := store.LoginState{
		IDHash:    hash(4),
		Username:  "alice",
		Kind:      "password",
		State:     state,
		ExpiresAt: t0.Add(time.Hour),
	}

	if err := m.PutLoginState(ctx, ls); err != nil {
		t.Fatal(err)
	}
	state[0] = 'X'

	gotLS, err := m.TakeLoginState(ctx, ls.IDHash, t0)
	if err != nil || string(gotLS.State) != "mutable" {
		t.Fatalf("login state input slice alias: %+v %v", gotLS, err)
	}

	key := []byte("mutable-key")
	sess := store.Session{
		IDHash:    hash(5),
		UserID:    uid,
		Key:       key,
		Scope:     "full",
		ExpiresAt: t0.Add(time.Hour),
	}

	if err := m.PutSession(ctx, sess); err != nil {
		t.Fatal(err)
	}
	key[0] = 'X'

	gotSess, err := m.SessionByIDHash(ctx, sess.IDHash, t0)
	if err != nil || string(gotSess.Key) != "mutable-key" {
		t.Fatalf("session input slice alias: %+v %v", gotSess, err)
	}

	if err := m.ReserveUsername(ctx, "temp", id(3), t0, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := m.PutLoginState(ctx, store.LoginState{
		IDHash:    hash(6),
		Username:  "temp",
		Kind:      "password",
		State:     []byte("x"),
		ExpiresAt: t0.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if err := m.PutSession(ctx, store.Session{
		IDHash:    hash(7),
		UserID:    uid,
		Scope:     "full",
		ExpiresAt: t0.Add(time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	if err := m.DeleteExpired(ctx, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	if err := m.ReserveUsername(ctx, "temp", id(4), t0.Add(time.Minute), t0.Add(2*time.Minute)); err != nil {
		t.Fatalf("expired reservation retained: %v", err)
	}
	if _, err := m.TakeLoginState(ctx, hash(6), t0.Add(time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired state retained: %v", err)
	}
	if _, err := m.SessionByIDHash(ctx, hash(7), t0.Add(time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expired session retained: %v", err)
	}
}
