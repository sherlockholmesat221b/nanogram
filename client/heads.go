// File: client/heads.go

package client

import (
	"fmt"
	"sync"
)

// Head is the newest version of a blob that this device has seen, with the
// hash of that blob.
type Head struct {
	Version uint64
	Hash    [32]byte
}

// HeadStore remembers the newest blob versions this device has seen. A server
// that later returns older or different data is caught by comparing with it.
// A device that has never logged in has nothing to compare with.
type HeadStore interface {
	Get(userID []byte, kind byte) (Head, bool)
	Put(userID []byte, kind byte, h Head) error
}

type memHeads struct {
	mu sync.Mutex
	m  map[string]Head
}

// NewMemHeads returns a HeadStore that keeps everything in memory.
func NewMemHeads() HeadStore {
	return &memHeads{m: make(map[string]Head)}
}

func headKey(userID []byte, kind byte) string {
	return string(userID) + string([]byte{kind})
}

func (h *memHeads) Get(userID []byte, kind byte) (Head, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()

	head, ok := h.m[headKey(userID, kind)]
	return head, ok
}

func (h *memHeads) Put(userID []byte, kind byte, head Head) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.m[headKey(userID, kind)] = head
	return nil
}

// checkHead compares what the server returned with what this device
// remembers.
//   - A lower version is a rollback.
//   - The same version with a different hash is tampering.
//   - The next version must be chained to the one this device saw: its
//     previous hash has to be the remembered hash, otherwise the server has
//     forked the history.
//   - Any higher version is allowed but reported, for example after a
//     password change on another device.
func checkHead(known Head, seen bool, version uint64, prev, hash [32]byte) (warning string, err error) {
	switch {
	case !seen:
		return "", nil

	case version < known.Version:
		return "", ErrRollback

	case version == known.Version && hash != known.Hash:
		return "", ErrTamper

	case version == known.Version+1 && prev != known.Hash:
		return "", ErrTamper

	case version > known.Version:
		return fmt.Sprintf(
			"changed since this device last saw it (version %d, now %d)",
			known.Version, version,
		), nil
	}

	return "", nil
}
