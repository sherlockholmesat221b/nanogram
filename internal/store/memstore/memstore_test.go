// File: internal/store/memstore/memstore_test.go

package memstore

import (
	"bytes"
	"context"
	"errors"
	"sync"
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

	if err := m.AdvanceCounter(ctx, hash(2), 1); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("counter for missing session: %v", err)
	}
	if err := m.AdvanceCounter(ctx, s.IDHash, 0); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("non-increasing counter: %v", err)
	}
	if err := m.AdvanceCounter(ctx, s.IDHash, 4); err != nil {
		t.Fatal(err)
	}
	if err := m.AdvanceCounter(ctx, s.IDHash, 3); !errors.Is(err, store.ErrConflict) {
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
