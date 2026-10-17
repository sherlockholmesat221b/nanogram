package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/bytemare/opaque"
)

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

func GenerateServerKeys(conf *opaque.Configuration) ServerKeys {
	privateKey, publicKey := conf.KeyGen()

	return ServerKeys{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		OPRFSeed:   conf.GenerateOPRFSeed(),
	}
}

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

	if writeErr != nil {
		return fmt.Errorf("write server keys file: %w", writeErr)
	}
	if syncErr != nil {
		return fmt.Errorf("sync server keys file: %w", syncErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close server keys file: %w", closeErr)
	}

	return nil
}

func LoadServerKeys(path string) (ServerKeys, error) {
	info, err := os.Stat(path)
	if err != nil {
		return ServerKeys{}, fmt.Errorf("stat server keys file: %w", err)
	}

	if info.Mode().Perm()&0o077 != 0 {
		return ServerKeys{}, errors.New(
			"server keys file permissions are too permissive",
		)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return ServerKeys{}, fmt.Errorf("read server keys file: %w", err)
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
