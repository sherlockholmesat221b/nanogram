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
		UserID:     uid,
		Kind:       "password",
		Record:     []byte("record"),
		KSFVersion: 1,
	}
	b := store.Blob{
		UserID:    uid,
		Kind:      store.BlobKindKEK,
		Version:   1,
		Data:      []byte("kek1"),
		CreatedAt: t0,
	}

	if err := m.CreateUser(ctx, u, []store.OpaqueRecord{r}, []store.Blob{b}, t0); err != nil {
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

	if err := m.CreateUser(ctx, store.User{ID: uid, Username: "alice"}, nil, nil, t0); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("without reservation: %v", err)
	}

	createUser(t, m, "alice", uid)

	if err := m.CreateUser(ctx, store.User{ID: id(2), Username: "alice"}, nil, nil, t0); !errors.Is(err, store.ErrTaken) {
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
	if err := m.CreateUser(ctx, store.User{ID: id(3), Username: "bob"}, nil, nil, t0); !errors.Is(err, store.ErrConflict) {
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

	if err := m.BeginPasswordChange(ctx, uid, 9, newRec, newKEK); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("wrong expected version: %v", err)
	}

	badVersion := newKEK
	badVersion.Version = 3
	if err := m.BeginPasswordChange(ctx, uid, 1, newRec, badVersion); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("wrong next version: %v", err)
	}

	if err := m.BeginPasswordChange(ctx, uid, 1, newRec, newKEK); err != nil {
		t.Fatal(err)
	}
	if err := m.BeginPasswordChange(ctx, uid, 1, newRec, newKEK); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("second pending change: %v", err)
	}

	if err := m.CommitPasswordChange(ctx, uid); err != nil {
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

	if err := m.CommitPasswordChange(ctx, uid); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("commit with no pending change: %v", err)
	}

	newRec.Record = []byte("aborted")
	newKEK.Version = 3
	newKEK.Data = []byte("kek3")

	if err := m.BeginPasswordChange(ctx, uid, 2, newRec, newKEK); err != nil {
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

	// Mutating the caller's original ID must not change stored user data.
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
