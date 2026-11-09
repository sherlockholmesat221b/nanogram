// File: client/pins_test.go

package client

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFingerprintGolden(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, 32)
	const want = "SHA256:cs1uhCLEB/ttCYaQ8RMLfe1+wvf14dML2dUh8BU2N5M"
	if got := Fingerprint(key); got != want {
		t.Fatalf("Fingerprint = %q, want %q; set the constant to this value", got, want)
	}
}

func TestFilePinsPutGetReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "pins.json")
	const server = "http://127.0.0.1:8080"

	store, err := NewFilePins(path, server)
	if err != nil {
		t.Fatal(err)
	}

	key := bytes.Repeat([]byte{0x42}, 32)
	if _, ok := store.Get(); ok {
		t.Fatal("a fresh store reported a pin")
	}
	if err := store.Put(key); err != nil {
		t.Fatal(err)
	}
	if got, ok := store.Get(); !ok || !bytes.Equal(got, key) {
		t.Fatalf("Get = (%x, %v)", got, ok)
	}

	reopened, err := NewFilePins(path, server)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := reopened.Get(); !ok || !bytes.Equal(got, key) {
		t.Fatalf("reopened Get = (%x, %v)", got, ok)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode %04o", info.Mode().Perm())
	}
}

func TestFilePinsServerMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.json")

	first, err := NewFilePins(path, "http://a")
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Put([]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}

	if _, err := NewFilePins(path, "http://b"); !errors.Is(err, ErrPinServerMismatch) {
		t.Fatalf("error = %v, want ErrPinServerMismatch", err)
	}
}

func TestFilePinsClear(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pins.json")

	store, err := NewFilePins(path, "http://x")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put([]byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := store.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("file still exists: %v", err)
	}
	// Clearing again is a no-op.
	if err := store.Clear(); err != nil {
		t.Fatalf("second Clear: %v", err)
	}
}
