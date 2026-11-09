// File: client/pins.go

package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// PinStore remembers the server's OPAQUE public key. A nil PinStore means
// no pinning: the client does not check and does not save.
type PinStore interface {
	Get() ([]byte, bool)
	Put(key []byte) error
	Clear() error
}

type memPins struct {
	mu  sync.Mutex
	key []byte
}

// NewMemPins returns an in-memory PinStore.
func NewMemPins() PinStore { return &memPins{} }

func (p *memPins) Get() ([]byte, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.key == nil {
		return nil, false
	}
	return append([]byte(nil), p.key...), true
}

func (p *memPins) Put(key []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.key = append([]byte(nil), key...)
	return nil
}

func (p *memPins) Clear() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.key = nil
	return nil
}

type pinFile struct {
	Version         int    `json:"version"`
	Server          string `json:"server"`
	ServerPublicKey []byte `json:"server_public_key"`
}

type filePins struct {
	mu     sync.Mutex
	path   string
	server string
	key    []byte
}

// NewFilePins loads a PinStore from a JSON file. A missing file yields an
// empty store. A file whose `server` field does not match the given server
// returns ErrPinServerMismatch: a pin belongs to exactly one server.
//
// The directory is created with mode 0700 when it does not exist. An
// existing directory is left alone, but refused when other users can write
// to it. The file itself must be a regular file, not a link, only readable
// by its owner.
func NewFilePins(path, server string) (PinStore, error) {
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
		return nil, errors.New("the pins directory is not a directory")
	case info.Mode().Perm()&0o022 != 0:
		return nil, errors.New("the pins directory is writable by other users")
	}

	p := &filePins{path: path, server: server}

	fileInfo, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	if !fileInfo.Mode().IsRegular() {
		return nil, errors.New("the pins file is not a regular file")
	}
	if fileInfo.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("the pins file permissions are too open")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var f pinFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("invalid pins file: %w", err)
	}
	if f.Version != 1 {
		return nil, errors.New("unsupported pins file version")
	}
	if f.Server != server {
		return nil, ErrPinServerMismatch
	}
	p.key = f.ServerPublicKey

	return p, nil
}

func (p *filePins) Get() ([]byte, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.key == nil {
		return nil, false
	}
	return append([]byte(nil), p.key...), true
}

func (p *filePins) Put(key []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.key = append([]byte(nil), key...)
	return p.writeFile()
}

func (p *filePins) Clear() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.key = nil
	err := os.Remove(p.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (p *filePins) writeFile() error {
	data, err := json.Marshal(pinFile{
		Version:         1,
		Server:          p.server,
		ServerPublicKey: p.key,
	})
	if err != nil {
		return err
	}

	dir := filepath.Dir(p.path)

	f, err := os.CreateTemp(dir, ".pins-*")
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
	if err := os.Rename(tmp, p.path); err != nil {
		return err
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
