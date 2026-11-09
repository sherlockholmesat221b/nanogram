// File: internal/tor/onion.go

// Package tor parses .onion addresses and reads Tor's onion-service key
// files. It does not talk to the Tor daemon; it only reads files the Tor
// process has written and computes what the client needs to verify the
// server's OPAQUE public key against its onion identity.
package tor

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

const (
	onionVersionByte = 3
	onionPubkeySize  = ed25519.PublicKeySize // 32
	onionChecksumLen = 2
	onionAddressSize = onionPubkeySize + onionChecksumLen + 1 // 35
	onionLabelLength = 56                                     // base32(35)

	secretKeyHeader = "== ed25519v1-secret: type0 ==\x00\x00\x00"
)

var (
	ErrNotOnionAddress = errors.New("not an onion address")
	ErrBadOnionFormat  = errors.New("invalid onion address")
	ErrBadOnionKey     = errors.New("unsupported onion key file")
)

// IsOnionAddress reports whether host ends in ".onion".
func IsOnionAddress(host string) bool {
	return strings.HasSuffix(strings.ToLower(strings.TrimSuffix(host, ".")), ".onion")
}

// ParseOnionAddress returns the 32-byte Ed25519 public key embedded in a
// v3 onion address. The address checksum is not verified: the caller
// verifies the server's signature against the returned key, and a bad
// checksum implies a bad key, so the signature check catches it.
func ParseOnionAddress(host string) ([]byte, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if !strings.HasSuffix(host, ".onion") {
		return nil, ErrNotOnionAddress
	}
	label := strings.TrimSuffix(host, ".onion")
	if len(label) != onionLabelLength {
		return nil, fmt.Errorf("%w: length %d, want %d", ErrBadOnionFormat, len(label), onionLabelLength)
	}

	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(label))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadOnionFormat, err)
	}
	if len(raw) != onionAddressSize {
		return nil, fmt.Errorf("%w: decoded length %d", ErrBadOnionFormat, len(raw))
	}
	if raw[onionPubkeySize+onionChecksumLen] != onionVersionByte {
		return nil, fmt.Errorf("%w: version %d, want %d", ErrBadOnionFormat, raw[onionPubkeySize+onionChecksumLen], onionVersionByte)
	}

	return append([]byte(nil), raw[:onionPubkeySize]...), nil
}

// LoadOnionKey reads a Tor hs_ed25519_secret_key file and returns the
// Ed25519 private key. Tor writes the file with a 32-byte header followed
// by either a 64-byte expanded key or a 32-byte seed, hex-encoded in some
// Tor versions and raw in others. All four combinations are accepted.
func LoadOnionKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	if bytes.HasPrefix(data, []byte(secretKeyHeader)) {
		data = data[len(secretKeyHeader):]
	}
	data = bytes.TrimRight(data, "\r\n")

	// A 64-byte input could be a raw 64-byte expanded key or a hex-encoded
	// 32-byte seed. Try hex first; a raw expanded key is astronomically
	// unlikely to be all hex digits.
	switch len(data) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(data), nil
	case ed25519.PrivateKeySize:
		if decoded, err := hex.DecodeString(string(data)); err == nil && len(decoded) == ed25519.SeedSize {
			return ed25519.NewKeyFromSeed(decoded), nil
		}
		return ed25519.PrivateKey(append([]byte(nil), data...)), nil
	case 2 * ed25519.PrivateKeySize:
		if decoded, err := hex.DecodeString(string(data)); err == nil && len(decoded) == ed25519.PrivateKeySize {
			return ed25519.PrivateKey(decoded), nil
		}
	}

	return nil, fmt.Errorf("%w: %d bytes after header", ErrBadOnionKey, len(data))
}
