package auth

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateSaveLoadServerKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server-keys.json")

	original := GenerateServerKeys(NewConfiguration())

	if len(original.PrivateKey) == 0 ||
		len(original.PublicKey) == 0 ||
		len(original.OPRFSeed) == 0 {
		t.Fatal("generated server keys contain empty fields")
	}

	if err := original.Save(path); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("file permissions = %04o, want 0600", info.Mode().Perm())
	}

	loaded, err := LoadServerKeys(path)
	if err != nil {
		t.Fatalf("LoadServerKeys() error: %v", err)
	}

	if !bytes.Equal(original.PrivateKey, loaded.PrivateKey) {
		t.Error("private keys differ")
	}
	if !bytes.Equal(original.PublicKey, loaded.PublicKey) {
		t.Error("public keys differ")
	}
	if !bytes.Equal(original.OPRFSeed, loaded.OPRFSeed) {
		t.Error("OPRF seeds differ")
	}
}

func TestSaveServerKeysRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server-keys.json")
	keys := GenerateServerKeys(NewConfiguration())

	if err := keys.Save(path); err != nil {
		t.Fatalf("first Save() error: %v", err)
	}

	if err := keys.Save(path); err == nil {
		t.Fatal("second Save() succeeded; want an error")
	}
}

func TestLoadServerKeysRejectsPermissivePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server-keys.json")
	keys := GenerateServerKeys(NewConfiguration())

	if err := keys.Save(path); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("Chmod() error: %v", err)
	}

	if _, err := LoadServerKeys(path); err == nil {
		t.Fatal("LoadServerKeys() accepted a file with mode 0644")
	}
}

func TestLoadServerKeysRejectsTruncatedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server-keys.json")

	if err := os.WriteFile(path, []byte(`{"version":1,"private_key":`), 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	if _, err := LoadServerKeys(path); err == nil {
		t.Fatal("LoadServerKeys() accepted truncated JSON")
	}
}

func TestLoadServerKeysRejectsUnsupportedVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server-keys.json")

	data := []byte(
		`{"version":2,"private_key":"AQ==","public_key":"Ag==","oprf_seed":"Aw=="}`,
	)

	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	if _, err := LoadServerKeys(path); err == nil {
		t.Fatal("LoadServerKeys() accepted version 2")
	}
}
