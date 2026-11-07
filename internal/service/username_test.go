// File: internal/service/username_test.go

package service

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func spellings(name string) []string {
	return []string{
		strings.ToUpper(name),
		strings.ToUpper(name[:1]) + name[1:],
		name,
	}
}

func TestUsernamesAreMatchedWithoutRegardToCase(t *testing.T) {
	f := newRegistrationFixture(t)
	userID := f.registerUser(t, false)

	stored, err := f.store.UserByUsername(context.Background(), testUsername)
	if err != nil {
		t.Fatalf("the account is not stored under the lowercase name: %v", err)
	}
	if stored.Username != strings.ToLower(testUsername) {
		t.Fatalf("stored name %q", stored.Username)
	}

	// Another spelling reaches the same account.
	for _, spelling := range spellings(testUsername) {
		attempt := f.attemptLogin(t, spelling, "password", testPassword)
		if attempt.err != nil {
			t.Fatalf("login as %q: %v", spelling, attempt.err)
		}
		if !bytes.Equal(attempt.start.UserID, userID) {
			t.Fatalf("login as %q reached another account", spelling)
		}

		if _, err := f.service.LoginFinish(context.Background(), attempt.start.LoginID, attempt.ke3); err != nil {
			t.Fatalf("finish login as %q: %v", spelling, err)
		}
	}
}

func TestOtherSpellingsOfATakenNameAreTaken(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, false)

	request := f.client(t).RegistrationInit([]byte(testPassword)).Serialize()

	for _, spelling := range spellings(testUsername) {
		_, err := f.service.RegisterStart(context.Background(), spelling, request, nil)
		if !errors.Is(err, ErrUsernameTaken) {
			t.Fatalf("%q: error = %v, want ErrUsernameTaken", spelling, err)
		}
	}
}

func TestUnknownNamesGetTheSameAnswerInAnyCase(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, false)

	lower := f.attemptLogin(t, "mallory", "password", testPassword)
	upper := f.attemptLogin(t, "MALLORY", "password", testPassword)

	if !bytes.Equal(lower.start.UserID, upper.start.UserID) {
		t.Fatal("an unknown name gets a different user id in another case")
	}
}
