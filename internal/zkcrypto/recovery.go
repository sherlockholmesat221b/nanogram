package zkcrypto

import (
	"crypto/rand"
	"errors"
	"strings"

	"github.com/tyler-smith/go-bip39"
)

var errInvalidRecoveryPhrase = errors.New("invalid recovery phrase")

// NewRecoveryKey returns a cryptographically random 32-byte recovery key.
func NewRecoveryKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// RecoveryPhrase encodes a 32-byte recovery key as a BIP39 English mnemonic.
func RecoveryPhrase(key []byte) (string, error) {
	if len(key) != 32 {
		return "", errors.New("recovery key must be 32 bytes")
	}
	return bip39.NewMnemonic(key)
}

// RecoveryKeyFromPhrase decodes a normalized 24-word BIP39 mnemonic into its
// original 32-byte entropy. The mnemonic is an encoding, not a seed source.
func RecoveryKeyFromPhrase(phrase string) ([]byte, error) {
	normalized := strings.ToLower(strings.Join(strings.Fields(strings.TrimSpace(phrase)), " "))
	if len(strings.Fields(normalized)) != 24 {
		return nil, errInvalidRecoveryPhrase
	}

	key, err := bip39.EntropyFromMnemonic(normalized)
	if err != nil || len(key) != 32 {
		return nil, errInvalidRecoveryPhrase
	}
	return key, nil
}

// RecoveryLoginSecret derives the login secret from a recovery key.
func RecoveryLoginSecret(key []byte) ([]byte, error) {
	return DeriveKey(key, LabelRecoveryLogin)
}

// RecoveryWrapKey derives the wrapping key from a recovery key.
func RecoveryWrapKey(key []byte) ([]byte, error) {
	return DeriveKey(key, LabelRecovery)
}
