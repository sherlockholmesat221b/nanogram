// File: client/fileheads.go

package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// fileHeads keeps the heads in one JSON file. It is safe for use by several
// goroutines, but not by several processes at once: the last write wins.
type fileHeads struct {
	mu    sync.Mutex
	path  string
	heads map[string]Head
}

var _ HeadStore = (*fileHeads)(nil)

// NewFileHeads loads a persistent, private store of blob heads.
//
// The directory is created with mode 0700 when it does not exist. An existing
// directory is left alone, but refused when other users can write to it, since
// they could replace or delete the file. The file itself must be a regular
// file (not a link) that only its owner can access.
func NewFileHeads(path string) (HeadStore, error) {
	dir := filepath.Dir(path)

	info, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	case !info.IsDir():
		return nil, errors.New("the heads directory is not a directory")
	case info.Mode().Perm()&0o022 != 0:
		return nil, errors.New("the heads directory is writable by other users")
	}

	h := &fileHeads{path: path, heads: make(map[string]Head)}

	fileInfo, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return h, nil
	}
	if err != nil {
		return nil, err
	}
	if !fileInfo.Mode().IsRegular() {
		return nil, errors.New("the heads file is not a regular file")
	}
	if fileInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("the heads file permissions are too open")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &h.heads); err != nil {
		return nil, fmt.Errorf("invalid heads file: %w", err)
	}
	if h.heads == nil {
		h.heads = make(map[string]Head)
	}

	return h, nil
}

func fileHeadKey(userID []byte, kind byte) string {
	return hex.EncodeToString(userID) + ":" + hex.EncodeToString([]byte{kind})
}

func (h *fileHeads) Get(userID []byte, kind byte) (Head, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	head, ok := h.heads[fileHeadKey(userID, kind)]
	return head, ok
}

// Put saves the head by writing a temporary file next to the real one and
// renaming it over it, so a crash never leaves a half-written file.
func (h *fileHeads) Put(userID []byte, kind byte, head Head) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	next := make(map[string]Head, len(h.heads)+1)
	for key, value := range h.heads {
		next[key] = value
	}
	next[fileHeadKey(userID, kind)] = head

	data, err := json.Marshal(next)
	if err != nil {
		return err
	}

	dir := filepath.Dir(h.path)

	f, err := os.CreateTemp(dir, ".heads-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)

	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, h.path); err != nil {
		return err
	}

	// Make the rename itself durable. Some systems cannot sync a directory,
	// and the data is already safe in the file, so failures are ignored.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}

	h.heads = next
	return nil
}
