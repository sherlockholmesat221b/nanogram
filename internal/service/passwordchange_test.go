// File: internal/service/passwordchange_test.go

package service

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

const newTestPassword = "a different password"

func kekUpload(version uint64) BlobUpload {
	return BlobUpload{
		Kind:     store.BlobKindKEK,
		Version:  version,
		PrevHash: [32]byte{1},
		Data:     bytes.Repeat([]byte{7}, 41),
	}
}

// newRecord asks the service for the registration answer for a new password
// and finishes it the way the client does.
func (f *registrationFixture) newRecord(t *testing.T, userID []byte, password string) []byte {
	t.Helper()

	c := f.client(t)
	request := c.RegistrationInit([]byte(password)).Serialize()

	response, err := f.service.PasswordChangeStart(context.Background(), userID, request)
	if err != nil {
		t.Fatalf("PasswordChangeStart: %v", err)
	}

	return identityRecord(t, c, response, userID)
}

func TestPasswordChangeCompletesWithProofOfTheNewPassword(t *testing.T) {
	f := newRegistrationFixture(t)
	userID := f.registerUser(t, false)
	ctx := context.Background()

	oldSession, oldKey := f.session(t, "password", testPassword)

	record := f.newRecord(t, userID, newTestPassword)
	if err := f.service.PasswordChangeBegin(ctx, userID, 1, record, kekUpload(2)); err != nil {
		t.Fatalf("PasswordChangeBegin: %v", err)
	}

	// Until the proof, the old password is the only one that works.
	if attempt := f.attemptLogin(t, testUsername, "password", testPassword); attempt.err != nil {
		t.Fatalf("old password during the change: %v", attempt.err)
	}
	if attempt := f.attemptLogin(t, testUsername, "password", newTestPassword); attempt.err == nil {
		t.Fatal("the new password worked before it was proven")
	}

	attempt := f.attemptLogin(t, testUsername, "pending", newTestPassword)
	if attempt.err != nil {
		t.Fatalf("the client could not prove the new password: %v", attempt.err)
	}

	info, err := f.service.LoginFinish(ctx, attempt.start.LoginID, attempt.ke3)
	if err != nil {
		t.Fatalf("LoginFinish: %v", err)
	}
	if info.Scope != "full" {
		t.Fatalf("scope = %q", info.Scope)
	}

	// The change is complete.
	if attempt := f.attemptLogin(t, testUsername, "password", testPassword); attempt.err == nil {
		t.Fatal("the old password still works")
	}
	if attempt := f.attemptLogin(t, testUsername, "password", newTestPassword); attempt.err != nil {
		t.Fatalf("the new password does not work: %v", attempt.err)
	}

	kek, err := f.store.CurrentBlob(ctx, userID, store.BlobKindKEK)
	if err != nil || kek.Version != 2 {
		t.Fatalf("current KEK: version %d, %v", kek.Version, err)
	}

	// Every older session ended.
	request := signed(oldKey, oldSession.SessionID, 1, "GET", "/v1/account/blobs", nil)
	if _, err := f.service.Authenticate(ctx, request, "full"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old session: error = %v, want ErrUnauthorized", err)
	}
}

func TestPendingLoginNeedsTheNewPassword(t *testing.T) {
	f := newRegistrationFixture(t)
	userID := f.registerUser(t, false)

	record := f.newRecord(t, userID, newTestPassword)
	if err := f.service.PasswordChangeBegin(context.Background(), userID, 1, record, kekUpload(2)); err != nil {
		t.Fatal(err)
	}

	if attempt := f.attemptLogin(t, testUsername, "pending", testPassword); attempt.err == nil {
		t.Fatal("the old password proved the new one")
	}
}

func TestPendingLoginWithoutAChangeLooksLikeAnyOtherUser(t *testing.T) {
	f := newRegistrationFixture(t)
	userID := f.registerUser(t, false)

	password := f.attemptLogin(t, testUsername, "password", testPassword)
	pending := f.attemptLogin(t, testUsername, "pending", testPassword)

	if !bytes.Equal(pending.start.UserID, userID) {
		t.Fatal("the user id differs from the real one")
	}
	if len(pending.start.KE2) != len(password.start.KE2) {
		t.Fatalf("KE2 lengths differ: %d and %d", len(password.start.KE2), len(pending.start.KE2))
	}
	if pending.err == nil {
		t.Fatal("the client finished a pending login without a pending change")
	}
}

func TestAPasswordChangeExpires(t *testing.T) {
	f := newRegistrationFixture(t)
	userID := f.registerUser(t, false)

	record := f.newRecord(t, userID, newTestPassword)
	if err := f.service.PasswordChangeBegin(context.Background(), userID, 1, record, kekUpload(2)); err != nil {
		t.Fatal(err)
	}

	f.now = f.now.Add(passwordChangeLifetime)

	if attempt := f.attemptLogin(t, testUsername, "pending", newTestPassword); attempt.err == nil {
		t.Fatal("an expired change could still be proven")
	}
	if attempt := f.attemptLogin(t, testUsername, "password", testPassword); attempt.err != nil {
		t.Fatalf("the old password stopped working: %v", attempt.err)
	}
}

func TestPasswordChangeConflicts(t *testing.T) {
	f := newRegistrationFixture(t)
	userID := f.registerUser(t, false)
	ctx := context.Background()

	record := f.newRecord(t, userID, newTestPassword)

	if err := f.service.PasswordChangeBegin(ctx, userID, 5, record, kekUpload(6)); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong current version: error = %v, want ErrConflict", err)
	}

	if err := f.service.PasswordChangeBegin(ctx, userID, 1, record, kekUpload(2)); err != nil {
		t.Fatal(err)
	}
	if err := f.service.PasswordChangeBegin(ctx, userID, 1, record, kekUpload(2)); !errors.Is(err, ErrConflict) {
		t.Fatalf("second change while one is pending: error = %v, want ErrConflict", err)
	}
}

func TestPasswordChangeValidatesTheRequest(t *testing.T) {
	f := newRegistrationFixture(t)
	userID := f.registerUser(t, false)
	ctx := context.Background()

	record := f.newRecord(t, userID, newTestPassword)

	wrongKind := kekUpload(2)
	wrongKind.Kind = store.BlobKindMEK

	tooShort := kekUpload(2)
	tooShort.Data = bytes.Repeat([]byte{7}, 40)

	tooLong := kekUpload(2)
	tooLong.Data = bytes.Repeat([]byte{7}, 4097)

	tests := []struct {
		name     string
		expected uint64
		record   []byte
		upload   BlobUpload
	}{
		{"wrong kind", 1, record, wrongKind},
		{"version does not follow", 1, record, kekUpload(3)},
		{"starting from version 0", 0, record, kekUpload(1)},
		{"blob too short", 1, record, tooShort},
		{"blob too long", 1, record, tooLong},
		{"garbage record", 1, []byte{1, 2, 3}, kekUpload(2)},
		{"no record", 1, nil, kekUpload(2)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := f.service.PasswordChangeBegin(ctx, userID, tt.expected, tt.record, tt.upload)
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestPasswordChangeStartRefusesGarbage(t *testing.T) {
	f := newRegistrationFixture(t)
	userID := f.registerUser(t, false)

	if _, err := f.service.PasswordChangeStart(context.Background(), userID, []byte{1, 2, 3}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error = %v, want ErrInvalidRequest", err)
	}
}
