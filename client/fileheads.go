// File: client/fileheads.go

package client

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type fileHeads struct {
	mu    sync.Mutex
	path  string
	heads map[string]Head
}

var _ HeadStore = (*fileHeads)(nil)

// NewFileHeads loads a persistent, private store of blob heads.
func NewFileHeads(path string) (HeadStore, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return nil, err
	}

	h := &fileHeads{path: path, heads: make(map[string]Head)}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return h, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("heads file is not a regular file")
	}
	if info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("heads file permissions are too open")
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

	if err := f.Chmod(0600); err != nil {
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

	h.heads = next
	return nil
}

// Keep the import list independent of platform-specific file permissions.
var _ = strings.Builder{}
