// File: client/onion_test.go

package client

import (
	"crypto/ed25519"
	"encoding/base32"
	"errors"
	"strings"
	"testing"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/zkcrypto"
)

// buildOnionAddress returns a well-formed v3 .onion address for pub. The
// checksum bytes are not meaningful; ParseOnionAddress does not verify them.
func buildOnionAddress(pub []byte) string {
	raw := make([]byte, 0, 35)
	raw = append(raw, pub...)
	raw = append(raw, 0, 0, 3)
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)) + ".onion"
}

func TestCheckOnionNotOnion(t *testing.T) {
	warn, err := CheckOnion("https://example.com", []byte{1}, nil)
	if warn != "" || err != nil {
		t.Fatalf("got %q, %v", warn, err)
	}
}

func TestCheckOnionUnsigned(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	addr := buildOnionAddress(pub)

	warn, err := CheckOnion("http://"+addr, []byte{1, 2, 3}, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if warn == "" {
		t.Fatal("expected a warning for an unsigned .onion")
	}
}

func TestCheckOnionVerified(t *testing.T) {
	onionPub, onionPriv, _ := ed25519.GenerateKey(nil)
	addr := buildOnionAddress(onionPub)

	opaqueKey := []byte("opaque-public-key")
	msg := append([]byte(zkcrypto.LabelOnion), opaqueKey...)
	sig := ed25519.Sign(onionPriv, msg)

	warn, err := CheckOnion("http://"+addr, opaqueKey, sig)
	if warn != "" || err != nil {
		t.Fatalf("got %q, %v", warn, err)
	}
}

func TestCheckOnionWrongSignature(t *testing.T) {
	onionPub, _, _ := ed25519.GenerateKey(nil)
	addr := buildOnionAddress(onionPub)

	_, otherPriv, _ := ed25519.GenerateKey(nil)
	opaqueKey := []byte("opaque-public-key")
	msg := append([]byte(zkcrypto.LabelOnion), opaqueKey...)
	sig := ed25519.Sign(otherPriv, msg)

	_, err := CheckOnion("http://"+addr, opaqueKey, sig)
	if !errors.Is(err, ErrServerKeyChanged) {
		t.Fatalf("error = %v, want ErrServerKeyChanged", err)
	}
}
