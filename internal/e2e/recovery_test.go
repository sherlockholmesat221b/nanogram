// File: internal/e2e/recovery_test.go

package e2e

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gitlab.com/sherlockholmesat221b/nanogram/client"
)

func TestRecoveryOverHTTP(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	pass := passphrase(t)

	result, err := s.client.Register(ctx, "alice", pass, pass, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Fields(result.RecoveryPhrase)) != 24 {
		t.Fatalf("phrase: %q", result.RecoveryPhrase)
	}

	const newPass = "Zq9$mK2#vL7@wN4!tR8x"

	session, err := s.client.RecoverWithPhrase(ctx, "alice", result.RecoveryPhrase, newPass, newPass)
	if err != nil {
		t.Fatalf("RecoverWithPhrase: %v", err)
	}

	if _, err := s.client.Login(ctx, "alice", pass); !errors.Is(err, client.ErrLoginFailed) {
		t.Fatalf("old password: %v", err)
	}
	if _, err := s.client.Login(ctx, "alice", newPass); err != nil {
		t.Fatalf("new password: %v", err)
	}

	newPhrase, err := s.client.RotateRecovery(ctx, session)
	if err != nil {
		t.Fatalf("RotateRecovery: %v", err)
	}
	if newPhrase == result.RecoveryPhrase {
		t.Fatal("the phrase did not change")
	}

	// Old phrase is dead.
	if _, err := s.client.RecoverWithPhrase(ctx, "alice", result.RecoveryPhrase, newPass, newPass); !errors.Is(err, client.ErrLoginFailed) {
		t.Fatalf("old phrase after rotation: %v", err)
	}
}
