// File: client/recovery_test.go

package client

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
)

func TestRecoverAndRotate(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()

	oldPassphrase, result := r.register(t, true)
	oldKEK := r.login(t, oldPassphrase).Account.KEK

	const newPass = "Zq9$mK2#vL7@wN4!tR8x"

	session, err := r.client.RecoverWithPhrase(ctx, "alice", result.RecoveryPhrase, newPass, newPass)
	if err != nil {
		t.Fatalf("RecoverWithPhrase: %v", err)
	}
	if !bytes.Equal(session.Account.KEK, oldKEK) {
		t.Fatal("the KEK changed")
	}
	if len(session.Warnings) != 0 {
		t.Fatalf("warnings: %v", session.Warnings)
	}

	// The old password is gone; the new one works.
	if _, err := r.client.Login(ctx, "alice", oldPassphrase); !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("old password: %v", err)
	}
	if _, err := r.client.Login(ctx, "alice", newPass); err != nil {
		t.Fatalf("new password: %v", err)
	}

	// Rotate the recovery phrase.
	newPhrase, err := r.client.RotateRecovery(ctx, session)
	if err != nil {
		t.Fatalf("RotateRecovery: %v", err)
	}
	if newPhrase == "" || newPhrase == result.RecoveryPhrase {
		t.Fatal("the phrase did not change")
	}

	// Old phrase no longer recovers; new one does.
	if _, err := r.client.RecoverWithPhrase(ctx, "alice", result.RecoveryPhrase, newPass, newPass); !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("old phrase: %v", err)
	}
}

func TestRecoverWithoutRotationKeepsThePhrase(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()

	oldPassphrase, result := r.register(t, true)

	const newPass = "Zq9$mK2#vL7@wN4!tR8x"
	if _, err := r.client.RecoverWithPhrase(ctx, "alice", result.RecoveryPhrase, newPass, newPass); err != nil {
		t.Fatalf("RecoverWithPhrase: %v", err)
	}

	// No rotation: the same phrase still works.
	const newerPass = "Yw8%nJ3$wM6@xP5!uS9z"
	if _, err := r.client.RecoverWithPhrase(ctx, "alice", result.RecoveryPhrase, newerPass, newerPass); err != nil {
		t.Fatalf("second recovery with the same phrase: %v", err)
	}
	_ = oldPassphrase
}

func TestRecoverWithoutRecoveryFailsLikeAWrongPhrase(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()

	r.register(t, false)

	const newPass = "Zq9$mK2#vL7@wN4!tR8x"
	// Any valid-looking 24-word phrase.
	phrase := "spatial where trade one wasp gather brown snap fire shy pact unit staff phrase piece element square rail hat wreck peace shrimp confirm trade"
	if _, err := r.client.RecoverWithPhrase(ctx, "alice", phrase, newPass, newPass); !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("error = %v, want ErrLoginFailed", err)
	}
}

func TestDisableRecovery(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()

	passphrase, _ := r.register(t, true)
	session := r.login(t, passphrase)

	if err := r.client.DisableRecovery(ctx, session); err != nil {
		t.Fatalf("DisableRecovery: %v", err)
	}
	// Idempotent.
	if err := r.client.DisableRecovery(ctx, session); err != nil {
		t.Fatalf("second DisableRecovery: %v", err)
	}

	// Rotation now fails: there is nothing to rotate.
	if _, err := r.client.RotateRecovery(ctx, session); !errors.Is(err, service.ErrRecoveryNotSetUp) {
		t.Fatalf("RotateRecovery: %v", err)
	}
}
