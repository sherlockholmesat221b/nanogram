// File: internal/tor/onion_test.go

package tor

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// DuckDuckGo's real v3 onion address. Used only for parsing; the
// checksum bytes are ignored by ParseOnionAddress.
const testOnion = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"

func TestIsOnionAddress(t *testing.T) {
	cases := map[string]bool{
		testOnion:           true,
		"abc.onion":         true,
		"ABC.ONION":         true,
		"abc.onion.":        true,
		"example.com":       false,
		"":                  false,
		"onion":             false,
		"tor.onion.evil.io": false,
	}
	for host, want := range cases {
		if got := IsOnionAddress(host); got != want {
			t.Fatalf("IsOnionAddress(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestParseOnionAddress(t *testing.T) {
	pub, err := ParseOnionAddress(testOnion)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 32 {
		t.Fatalf("length %d", len(pub))
	}

	label := strings.TrimSuffix(testOnion, ".onion")
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(label))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pub, raw[:32]) {
		t.Fatal("parsed key does not match the decoded address")
	}
}

func TestParseOnionAddressRejects(t *testing.T) {
	cases := map[string]error{
		"example.com": ErrNotOnionAddress,
		"short.onion": ErrBadOnionFormat,
	}
	for addr, wantErr := range cases {
		_, err := ParseOnionAddress(addr)
		if !errors.Is(err, wantErr) {
			t.Fatalf("%q: error = %v, want %v", addr, err, wantErr)
		}
	}
}

func writeKeyFile(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hs_ed25519_secret_key")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadOnionKeyRaw(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	path := writeKeyFile(t, append([]byte(secretKeyHeader), []byte(priv)...))

	loaded, err := LoadOnionKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded, priv) {
		t.Fatal("loaded key does not match")
	}
}

func TestLoadOnionKeyHex(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	path := writeKeyFile(t, append([]byte(secretKeyHeader), []byte(hex.EncodeToString(priv))...))

	loaded, err := LoadOnionKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded, priv) {
		t.Fatal("loaded key does not match")
	}
}

func TestLoadOnionKeySeed(t *testing.T) {
	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	want := ed25519.NewKeyFromSeed(seed)
	path := writeKeyFile(t, append([]byte(secretKeyHeader), seed...))

	loaded, err := LoadOnionKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded, want) {
		t.Fatal("loaded key does not match")
	}
}

func TestLoadOnionKeyGarbage(t *testing.T) {
	path := writeKeyFile(t, []byte("not a key"))
	if _, err := LoadOnionKey(path); !errors.Is(err, ErrBadOnionKey) {
		t.Fatalf("error = %v, want ErrBadOnionKey", err)
	}
}
