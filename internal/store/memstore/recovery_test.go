// File: internal/store/memstore/recovery_test.go

package memstore

import (
	"errors"
	"testing"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

func TestReplaceRecovery(t *testing.T) {
	m := New()
	uid := id(1)
	createUser(t, m, "alice", uid)

	rec := store.OpaqueRecord{
		UserID:     uid,
		Kind:       "recovery",
		Record:     []byte("rec1"),
		KSFVersion: 1,
	}
	blob := store.Blob{
		UserID:  uid,
		Kind:    store.BlobKindRecovery,
		Version: 1,
		Data:    []byte("recblob1"),
	}

	if err := m.ReplaceRecovery(ctx, uid, rec, blob); err != nil {
		t.Fatalf("replace first recovery: %v", err)
	}

	gotRec, err := m.CurrentOpaqueRecord(ctx, uid, "recovery")
	if err != nil {
		t.Fatal(err)
	}
	if string(gotRec.Record) != "rec1" {
		t.Fatalf("recovery record = %q, want rec1", gotRec.Record)
	}

	gotBlob, err := m.CurrentBlob(ctx, uid, store.BlobKindRecovery)
	if err != nil {
		t.Fatal(err)
	}
	if gotBlob.Version != 1 || string(gotBlob.Data) != "recblob1" {
		t.Fatalf("recovery blob = %+v", gotBlob)
	}

	rec2 := store.OpaqueRecord{
		UserID:     uid,
		Kind:       "recovery",
		Record:     []byte("rec2"),
		KSFVersion: 1,
	}
	blob2 := store.Blob{
		UserID:  uid,
		Kind:    store.BlobKindRecovery,
		Version: 2,
		Data:    []byte("recblob2"),
	}
	if err := m.ReplaceRecovery(ctx, uid, rec2, blob2); err != nil {
		t.Fatalf("replace second recovery: %v", err)
	}

	gotRec, err = m.CurrentOpaqueRecord(ctx, uid, "recovery")
	if err != nil {
		t.Fatal(err)
	}
	if string(gotRec.Record) != "rec2" {
		t.Fatalf("replacement recovery record = %q, want rec2", gotRec.Record)
	}

	gotBlob, err = m.CurrentBlob(ctx, uid, store.BlobKindRecovery)
	if err != nil {
		t.Fatal(err)
	}
	if gotBlob.Version != 2 || string(gotBlob.Data) != "recblob2" {
		t.Fatalf("replacement recovery blob = %+v", gotBlob)
	}

	wrongVersionBlob := store.Blob{
		UserID:  uid,
		Kind:    store.BlobKindRecovery,
		Version: 4,
		Data:    []byte("wrong-version"),
	}
	if err := m.ReplaceRecovery(ctx, uid, rec2, wrongVersionBlob); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("wrong recovery version error = %v, want ErrConflict", err)
	}

	missingUID := id(9)
	missingRec := store.OpaqueRecord{
		UserID: missingUID,
		Kind:   "recovery",
		Record: []byte("missing"),
	}
	missingBlob := store.Blob{
		UserID:  missingUID,
		Kind:    store.BlobKindRecovery,
		Version: 1,
		Data:    []byte("missing"),
	}
	if err := m.ReplaceRecovery(ctx, missingUID, missingRec, missingBlob); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("missing user error = %v, want ErrNotFound", err)
	}
}

func TestDeleteRecovery(t *testing.T) {
	m := New()
	uid := id(1)
	createUser(t, m, "alice", uid)

	rec := store.OpaqueRecord{
		UserID: uid,
		Kind:   "recovery",
		Record: []byte("recovery-record"),
	}
	blob := store.Blob{
		UserID:  uid,
		Kind:    store.BlobKindRecovery,
		Version: 1,
		Data:    []byte("recovery-blob"),
	}
	if err := m.ReplaceRecovery(ctx, uid, rec, blob); err != nil {
		t.Fatal(err)
	}

	if err := m.DeleteRecovery(ctx, uid); err != nil {
		t.Fatalf("delete recovery: %v", err)
	}
	if _, err := m.CurrentOpaqueRecord(ctx, uid, "recovery"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("recovery record after deletion error = %v", err)
	}
	if _, err := m.CurrentBlob(ctx, uid, store.BlobKindRecovery); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("recovery blob after deletion error = %v", err)
	}

	if err := m.DeleteRecovery(ctx, uid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("delete missing recovery error = %v", err)
	}
}
