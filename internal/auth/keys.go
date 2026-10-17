package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/bytemare/opaque"
)

// ServerKeys holds the server's OPAQUE private key, public key, and OPRF seed.
// Save and LoadServerKeys preserve these values using the versioned JSON format.
type ServerKeys struct {
	PrivateKey []byte
	PublicKey  []byte
	OPRFSeed   []byte
}

type serverKeysFile struct {
	Version    int    `json:"version"`
	PrivateKey []byte `json:"private_key"`
	PublicKey  []byte `json:"public_key"`
	OPRFSeed   []byte `json:"oprf_seed"`
}

// GenerateServerKeys generates a matching OPAQUE key pair and a fresh OPRF seed.
func GenerateServerKeys(conf *opaque.Configuration) ServerKeys {
	privateKey, publicKey := conf.KeyGen()

	return ServerKeys{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		OPRFSeed:   conf.GenerateOPRFSeed(),
	}
}

// Save writes the keys as versioned JSON to a file with mode 0600.
// It never overwrites an existing path and removes a newly created file on failure.
func (k ServerKeys) Save(path string) error {
	data, err := json.Marshal(serverKeysFile{
		Version:    1,
		PrivateKey: k.PrivateKey,
		PublicKey:  k.PublicKey,
		OPRFSeed:   k.OPRFSeed,
	})
	if err != nil {
		return fmt.Errorf("marshal server keys: %w", err)
	}

	file, err := os.OpenFile(
		path,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0600,
	)
	if err != nil {
		return fmt.Errorf("create server keys file: %w", err)
	}

	n, writeErr := file.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}

	var syncErr error
	if writeErr == nil {
		syncErr = file.Sync()
	}

	closeErr := file.Close()

	if writeErr != nil || syncErr != nil || closeErr != nil {
		_ = os.Remove(path)

		if writeErr != nil {
			return fmt.Errorf("write server keys file: %w", writeErr)
		}
		if syncErr != nil {
			return fmt.Errorf("sync server keys file: %w", syncErr)
		}
		return fmt.Errorf("close server keys file: %w", closeErr)
	}

	return nil
}

// LoadServerKeys loads versioned JSON from a regular file, rejecting
// files accessible to group or others and reading at most 64 KiB.
func LoadServerKeys(path string) (ServerKeys, error) {
	file, err := os.Open(path)
	if err != nil {
		return ServerKeys{}, errors.New("cannot open server keys file")
	}

	info, statErr := file.Stat()
	if statErr != nil {
		_ = file.Close()
		return ServerKeys{}, errors.New("cannot inspect server keys file")
	}

	if !info.Mode().IsRegular() {
		_ = file.Close()
		return ServerKeys{}, errors.New("server keys path is not a regular file")
	}

	if info.Mode().Perm()&0o077 != 0 {
		_ = file.Close()
		return ServerKeys{}, errors.New(
			"server keys file permissions are too permissive",
		)
	}

	data, readErr := io.ReadAll(io.LimitReader(file, 1<<16))
	closeErr := file.Close()

	if readErr != nil {
		return ServerKeys{}, errors.New("cannot read server keys file")
	}
	if closeErr != nil {
		return ServerKeys{}, errors.New("cannot close server keys file")
	}

	var stored serverKeysFile
	if err := json.Unmarshal(data, &stored); err != nil {
		return ServerKeys{}, errors.New("invalid server keys file format")
	}

	if stored.Version != 1 {
		return ServerKeys{}, errors.New("unsupported server keys file version")
	}

	if len(stored.PrivateKey) == 0 ||
		len(stored.PublicKey) == 0 ||
		len(stored.OPRFSeed) == 0 {
		return ServerKeys{}, errors.New("server keys file contains empty key fields")
	}

	return ServerKeys{
		PrivateKey: stored.PrivateKey,
		PublicKey:  stored.PublicKey,
		OPRFSeed:   stored.OPRFSeed,
	}, nil
}
