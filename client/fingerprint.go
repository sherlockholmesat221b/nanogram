// File: client/fingerprint.go

package client

import (
	"crypto/sha256"
	"encoding/base64"
)

// Fingerprint returns a short, printable representation of a public key,
// in the SSH format: "SHA256:" followed by the raw base64 (no padding) of
// SHA-256(key). The format is part of what the operator publishes and what
// the user compares; do not change it without a version bump.
func Fingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}
