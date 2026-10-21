// File: client/fileheads_test.go

package client

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileHeadsPutGetReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "heads.json")

	store, err := NewFileHeads(path)
	if err != nil {
		t.Fatal(err)
	}

	userID := []byte{1, 2, 3}
	head := Head{Version: 7, Hash: [32]byte{9, 8, 7}}

	if _, ok := store.Get(userID, 1); ok {
		t.Fatal("unexpected head")
	}
	if err := store.Put(userID, 1, head); err != nil {
		t.Fatal(err)
	}
	got, ok := store.Get(userID, 1)
	if !ok || got != head {
		t.Fatalf("Get() = (%+v, %v), want (%+v, true)", got, ok, head)
	}

	reopened, err := NewFileHeads(path)
	if err != nil {
		t.Fatal(err)
	}
	got, ok = reopened.Get(userID, 1)
	if !ok || got != head {
		t.Fatalf("reopened Get() = (%+v, %v), want (%+v, true)", got, ok, head)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("file mode = %04o, want 0600", got)
	}
}

func TestFileHeadsRejectsOpenPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heads.json")
	if err := os.WriteFile(path, []byte("{}"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 == 0 {
		t.Fatalf("test filesystem does not expose group/other permissions: mode %04o", info.Mode().Perm())
	}

	if _, err := NewFileHeads(path); err == nil {
		t.Fatalf("NewFileHeads accepted a file with mode %04o", info.Mode().Perm())
	}
}
