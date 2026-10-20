// File: internal/store/memstore/records_test.go

package memstore

import (
	"errors"
	"testing"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

func TestCurrentOpaqueAndBlob(t *testing.T) {
	m := New()
	uid := id(1)
	createUser(t, m, "alice", uid)

	if _, err := m.CurrentOpaqueRecord(ctx, uid, "recovery"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing opaque record: %v", err)
	}

	r, err := m.CurrentOpaqueRecord(ctx, uid, "password")
	if err != nil {
		t.Fatal(err)
	}
	if string(r.Record) != "record" {
		t.Fatalf("record=%q", r.Record)
	}

	if _, err := m.CurrentBlob(ctx, uid, store.BlobKindMEK); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing blob: %v", err)
	}

	b, err := m.CurrentBlob(ctx, uid, store.BlobKindKEK)
	if err != nil {
		t.Fatal(err)
	}
	if b.Version != 1 || string(b.Data) != "kek1" {
		t.Fatalf("blob=%+v", b)
	}

	err = m.BeginPasswordChange(
		ctx,
		uid,
		1,
		store.OpaqueRecord{UserID: uid, Kind: "password", Pending: true, Record: []byte("new")},
		store.Blob{UserID: uid, Kind: store.BlobKindKEK, Version: 2, Pending: true, Data: []byte("kek2")},
		t0,
		t0.Add(time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}

	b, err = m.CurrentBlob(ctx, uid, store.BlobKindKEK)
	if err != nil || b.Version != 1 {
		t.Fatalf("pending blob became current: %+v, %v", b, err)
	}
}

func TestAppendBlob(t *testing.T) {
	m := New()
	uid := id(1)
	createUser(t, m, "alice", uid)

	pendingB := store.Blob{
		UserID:  uid,
		Kind:    store.BlobKindMEK,
		Version: 1,
		Pending: true,
	}
	if err := m.AppendBlob(ctx, pendingB); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("append pending blob error = %v", err)
	}

	wrongVer := store.Blob{
		UserID:  uid,
		Kind:    store.BlobKindMEK,
		Version: 2,
		Data:    []byte("mek2"),
	}
	if err := m.AppendBlob(ctx, wrongVer); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("append wrong version error = %v", err)
	}

	validMEK1 := store.Blob{
		UserID:  uid,
		Kind:    store.BlobKindMEK,
		Version: 1,
		Data:    []byte("mek1"),
	}
	if err := m.AppendBlob(ctx, validMEK1); err != nil {
		t.Fatalf("append first MEK: %v", err)
	}

	validMEK2 := store.Blob{
		UserID:  uid,
		Kind:    store.BlobKindMEK,
		Version: 2,
		Data:    []byte("mek2"),
	}
	if err := m.AppendBlob(ctx, validMEK2); err != nil {
		t.Fatalf("append second MEK: %v", err)
	}

	versionZero := store.Blob{
		UserID:  uid,
		Kind:    store.BlobKindMEK,
		Version: 0,
		Data:    []byte("mek0"),
	}
	if err := m.AppendBlob(ctx, versionZero); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("append version zero for existing kind error = %v", err)
	}

	kek := store.Blob{
		UserID:  uid,
		Kind:    store.BlobKindKEK,
		Version: 2,
		Data:    []byte("kek2"),
	}
	if err := m.AppendBlob(ctx, kek); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("append KEK error = %v, want ErrConflict", err)
	}

	recovery := store.Blob{
		UserID:  uid,
		Kind:    store.BlobKindRecovery,
		Version: 1,
		Data:    []byte("recovery1"),
	}
	if err := m.AppendBlob(ctx, recovery); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("append recovery blob error = %v, want ErrConflict", err)
	}

	current, err := m.CurrentBlob(ctx, uid, store.BlobKindMEK)
	if err != nil {
		t.Fatal(err)
	}
	if current.Version != 2 || string(current.Data) != "mek2" {
		t.Fatalf("current MEK = %+v, want version 2", current)
	}
}
