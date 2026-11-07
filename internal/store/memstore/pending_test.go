// File: internal/store/memstore/pending_test.go

package memstore

import (
	"errors"
	"testing"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

func TestPendingOpaqueRecord(t *testing.T) {
	m := New()
	uid := id(1)
	createUser(t, m, "alice", uid)

	if _, err := m.PendingOpaqueRecord(ctx, uid, "password", t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("before any change: %v", err)
	}

	rec := store.OpaqueRecord{UserID: uid, Kind: "password", Pending: true, Record: []byte("new")}
	kek := store.Blob{UserID: uid, Kind: store.BlobKindKEK, Version: 2, Pending: true, Data: []byte("kek2")}

	if err := m.BeginPasswordChange(ctx, uid, 1, rec, kek, t0, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	got, err := m.PendingOpaqueRecord(ctx, uid, "password", t0.Add(time.Minute))
	if err != nil || string(got.Record) != "new" {
		t.Fatalf("pending record: %+v, %v", got, err)
	}

	current, err := m.CurrentOpaqueRecord(ctx, uid, "password")
	if err != nil || string(current.Record) != "record" {
		t.Fatalf("the current record changed: %+v, %v", current, err)
	}

	if _, err := m.PendingOpaqueRecord(ctx, uid, "recovery", t0.Add(time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another kind: %v", err)
	}

	if _, err := m.PendingOpaqueRecord(ctx, uid, "password", t0.Add(time.Hour)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("at the expiry: %v", err)
	}

	if err := m.CommitPasswordChange(ctx, uid, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := m.PendingOpaqueRecord(ctx, uid, "password", t0.Add(time.Minute)); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("after the commit: %v", err)
	}
}
