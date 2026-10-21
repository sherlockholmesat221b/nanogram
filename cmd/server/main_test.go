// File: cmd/server/main_test.go

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitKeysCreatesAFileOnlyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server-keys.json")

	var out, errOut bytes.Buffer

	if err := run([]string{"-init-keys", "-keys", path}, &out, &errOut); err != nil {
		t.Fatalf("first -init-keys: %v", err)
	}
	if !strings.Contains(out.String(), path) {
		t.Fatalf("output %q", out.String())
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v", info.Mode().Perm())
	}

	if err := run([]string{"-init-keys", "-keys", path}, &out, &errOut); err == nil {
		t.Fatal("a second -init-keys overwrote the key file")
	}
}

func TestBuildRefusesMissingAndOpenKeyFiles(t *testing.T) {
	dir := t.TempDir()

	if _, _, err := build(filepath.Join(dir, "missing.json"), nil); err == nil {
		t.Fatal("a missing key file was accepted")
	}

	path := filepath.Join(dir, "server-keys.json")
	var out, errOut bytes.Buffer
	if err := run([]string{"-init-keys", "-keys", path}, &out, &errOut); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := build(path, nil); err == nil {
		t.Fatal("a key file readable by others was accepted")
	}
}

func TestBuiltHandlerAnswersInJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server-keys.json")
	var out, errOut bytes.Buffer
	if err := run([]string{"-init-keys", "-keys", path}, &out, &errOut); err != nil {
		t.Fatal(err)
	}

	_, handler, err := build(path, nil)
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest("POST", "/v1/login/start", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
}
