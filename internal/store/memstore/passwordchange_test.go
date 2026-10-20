// File: internal/store/memstore/passwordchange_test.go

package memstore

import (
	"errors"
	"testing"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

func TestPasswordChangeCommitAndAbort(t *testing.T) {
	m := New()
	uid := id(1)
	createUser(t, m, "alice", uid)

	newRec := store.OpaqueRecord{
		UserID:     uid,
		Kind:       "password",
		Pending:    true,
		Record:     []byte("new-record"),
		KSFVersion: 2,
	}
	newKEK := store.Blob{
		UserID:    uid,
		Kind:      store.BlobKindKEK,
		Version:   2,
		Pending:   true,
		Data:      []byte("kek2"),
		CreatedAt: t0,
	}

	if err := m.BeginPasswordChange(ctx, uid, 9, newRec, newKEK, t0, t0.Add(time.Hour)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("wrong expected version: %v", err)
	}

	badVersion := newKEK
	badVersion.Version = 3
	if err := m.BeginPasswordChange(ctx, uid, 1, newRec, badVersion, t0, t0.Add(time.Hour)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("wrong next version: %v", err)
	}

	if err := m.BeginPasswordChange(ctx, uid, 1, newRec, newKEK, t0, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := m.BeginPasswordChange(ctx, uid, 1, newRec, newKEK, t0, t0.Add(time.Hour)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second pending change: %v", err)
	}

	if err := m.CommitPasswordChange(ctx, uid, t0); err != nil {
		t.Fatal(err)
	}

	r, err := m.CurrentOpaqueRecord(ctx, uid, "password")
	if err != nil || string(r.Record) != "new-record" || r.Pending {
		t.Fatalf("committed record=%+v err=%v", r, err)
	}

	b, err := m.CurrentBlob(ctx, uid, store.BlobKindKEK)
	if err != nil || b.Version != 2 || b.Pending {
		t.Fatalf("committed blob=%+v err=%v", b, err)
	}

	if err := m.CommitPasswordChange(ctx, uid, t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("commit with no pending change: %v", err)
	}

	newRec.Record = []byte("aborted")
	newKEK.Version = 3
	newKEK.Data = []byte("kek3")

	if err := m.BeginPasswordChange(ctx, uid, 2, newRec, newKEK, t0, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := m.AbortPasswordChange(ctx, uid); err != nil {
		t.Fatal(err)
	}

	r, err = m.CurrentOpaqueRecord(ctx, uid, "password")
	if err != nil || string(r.Record) != "new-record" {
		t.Fatalf("abort changed current record: %+v err=%v", r, err)
	}

	b, err = m.CurrentBlob(ctx, uid, store.BlobKindKEK)
	if err != nil || b.Version != 2 {
		t.Fatalf("abort changed current blob: %+v err=%v", b, err)
	}

	if err := m.AbortPasswordChange(ctx, uid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("abort with no pending change: %v", err)
	}
}

func TestPasswordChangeExpiry(t *testing.T) {
	m := New()
	uid := id(1)
	createUser(t, m, "alice", uid)

	newRec := store.OpaqueRecord{
		UserID:     uid,
		Kind:       "password",
		Pending:    true,
		Record:     []byte("expire-record"),
		KSFVersion: 2,
	}
	newKEK := store.Blob{
		UserID:    uid,
		Kind:      store.BlobKindKEK,
		Version:   2,
		Pending:   true,
		Data:      []byte("kek2"),
		CreatedAt: t0,
	}

	if err := m.BeginPasswordChange(ctx, uid, 1, newRec, newKEK, t0, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	// Before expiry, starting another should conflict.
	if err := m.BeginPasswordChange(ctx, uid, 1, newRec, newKEK, t0.Add(30*time.Minute), t0.Add(time.Hour)); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("expected conflict before expiry, got %v", err)
	}

	// Delete expired at t0.Add(2*time.Hour).
	if err := m.DeleteExpired(ctx, t0.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}

	// Now a new BeginPasswordChange should succeed.
	if err := m.BeginPasswordChange(ctx, uid, 1, newRec, newKEK, t0.Add(2*time.Hour), t0.Add(3*time.Hour)); err != nil {
		t.Fatalf("expected success after expiry deletion, got %v", err)
	}
}

func TestBeginPasswordChangeExpiredPending(t *testing.T) {
	m := New()
	uid := id(1)
	createUser(t, m, "alice", uid)

	expiry := t0.Add(time.Hour)

	firstRec := store.OpaqueRecord{
		UserID:     uid,
		Kind:       "password",
		Pending:    true,
		Record:     []byte("first-record"),
		KSFVersion: 2,
	}
	firstKEK := store.Blob{
		UserID:    uid,
		Kind:      store.BlobKindKEK,
		Version:   2,
		Pending:   true,
		Data:      []byte("first-kek"),
		CreatedAt: t0,
	}

	if err := m.BeginPasswordChange(ctx, uid, 1, firstRec, firstKEK, t0, expiry); err != nil {
		t.Fatal(err)
	}

	secondRec := store.OpaqueRecord{
		UserID:     uid,
		Kind:       "password",
		Pending:    true,
		Record:     []byte("second-record"),
		KSFVersion: 3,
	}
	secondKEK := store.Blob{
		UserID:    uid,
		Kind:      store.BlobKindKEK,
		Version:   2,
		Pending:   true,
		Data:      []byte("second-kek"),
		CreatedAt: expiry,
	}

	// Expiry is inclusive: until == now means the pending change has expired.
	// This must succeed without calling DeleteExpired.
	if err := m.BeginPasswordChange(ctx, uid, 1, secondRec, secondKEK, expiry, expiry.Add(time.Hour)); err != nil {
		t.Fatalf("new password change blocked by expired pending change: %v", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	pendingRec, ok := m.opaque[opaqueKey{
		userID:  string(uid),
		kind:    "password",
		pending: true,
	}]
	if !ok {
		t.Fatal("replacement pending password record not found")
	}
	if string(pendingRec.Record) != "second-record" {
		t.Fatalf("pending record = %q, want second-record", pendingRec.Record)
	}

	pendingBlob, ok := m.blobs[blobKey{
		userID:  string(uid),
		kind:    store.BlobKindKEK,
		version: 2,
	}]
	if !ok {
		t.Fatal("replacement pending KEK not found")
	}
	if string(pendingBlob.Data) != "second-kek" || !pendingBlob.Pending {
		t.Fatalf("pending KEK = %+v, want replacement pending KEK", pendingBlob)
	}
	if got := m.expiries[string(uid)]; !got.Equal(expiry.Add(time.Hour)) {
		t.Fatalf("pending expiry = %v, want %v", got, expiry.Add(time.Hour))
	}
}

func TestCommitPasswordChangeExpiredPending(t *testing.T) {
	m := New()
	uid := id(1)
	createUser(t, m, "alice", uid)

	expiry := t0.Add(time.Hour)
	rec := store.OpaqueRecord{
		UserID:  uid,
		Kind:    "password",
		Pending: true,
		Record:  []byte("new-record"),
	}
	kek := store.Blob{
		UserID:  uid,
		Kind:    store.BlobKindKEK,
		Version: 2,
		Pending: true,
		Data:    []byte("kek2"),
	}

	if err := m.BeginPasswordChange(ctx, uid, 1, rec, kek, t0, expiry); err != nil {
		t.Fatal(err)
	}

	if err := m.CommitPasswordChange(ctx, uid, expiry); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("commit at expiry = %v, want ErrNotFound", err)
	}

	gotRec, err := m.CurrentOpaqueRecord(ctx, uid, "password")
	if err != nil {
		t.Fatal(err)
	}
	if string(gotRec.Record) != "record" {
		t.Fatalf("current password record changed after expired commit: %q", gotRec.Record)
	}

	gotKEK, err := m.CurrentBlob(ctx, uid, store.BlobKindKEK)
	if err != nil {
		t.Fatal(err)
	}
	if gotKEK.Version != 1 {
		t.Fatalf("current KEK version = %d, want 1", gotKEK.Version)
	}
}

func TestCommitPasswordChangeMissingPending(t *testing.T) {
	m := New()
	uid := id(1)
	createUser(t, m, "alice", uid)

	if err := m.CommitPasswordChange(ctx, uid, t0); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("commit without pending change = %v, want ErrNotFound", err)
	}
}
