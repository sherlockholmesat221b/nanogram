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
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("file mode = %04o, want 0600", got)
	}

	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("a new directory has mode %04o, want 0700", got)
	}
}

func TestFileHeadsKeepsEveryHead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heads.json")

	store, err := NewFileHeads(path)
	if err != nil {
		t.Fatal(err)
	}

	heads := map[string]Head{}
	for i, kind := range []byte{1, 2, 3} {
		for _, user := range [][]byte{{1}, {2}} {
			head := Head{Version: uint64(i + 1), Hash: [32]byte{byte(i), user[0]}}
			heads[fileHeadKey(user, kind)] = head

			if err := store.Put(user, kind, head); err != nil {
				t.Fatal(err)
			}
		}
	}

	reopened, err := NewFileHeads(path)
	if err != nil {
		t.Fatal(err)
	}

	for i, kind := range []byte{1, 2, 3} {
		for _, user := range [][]byte{{1}, {2}} {
			got, ok := reopened.Get(user, kind)
			if !ok || got != heads[fileHeadKey(user, kind)] {
				t.Fatalf("head %d for user %d: (%+v, %v)", i, user[0], got, ok)
			}
		}
	}
}

func TestFileHeadsLeavesNoTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "heads.json")

	store, err := NewFileHeads(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := store.Put([]byte{1}, 1, Head{Version: uint64(i + 1)}); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "heads.json" {
		t.Fatalf("directory holds %d entries, first %q", len(entries), entries[0].Name())
	}
}

func TestFileHeadsRejectsOpenPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heads.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 == 0 {
		t.Skipf("this filesystem does not keep group and other permissions: mode %04o", info.Mode().Perm())
	}

	if _, err := NewFileHeads(path); err == nil {
		t.Fatalf("NewFileHeads accepted a file with mode %04o", info.Mode().Perm())
	}
}

func TestFileHeadsRejectsABrokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "heads.json")
	if err := os.WriteFile(path, []byte("this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := NewFileHeads(path); err == nil {
		t.Fatal("a broken file was accepted")
	}
}

func TestFileHeadsRejectsALink(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.json")
	link := filepath.Join(dir, "heads.json")

	if err := os.WriteFile(real, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symbolic links are not available: %v", err)
	}

	if _, err := NewFileHeads(link); err == nil {
		t.Fatal("a symbolic link was accepted")
	}
}

func TestFileHeadsLeavesAnExistingDirectoryAlone(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	if _, err := NewFileHeads(filepath.Join(dir, "heads.json")); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("the directory mode was changed to %04o", got)
	}
}

func TestFileHeadsRefusesADirectoryOthersCanWrite(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o022 == 0 {
		t.Skip("this filesystem does not keep group and other permissions")
	}

	if _, err := NewFileHeads(filepath.Join(dir, "heads.json")); err == nil {
		t.Fatal("a directory writable by others was accepted")
	}
}
