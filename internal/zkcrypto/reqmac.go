// File: internal/zkcrypto/reqmac.go

package zkcrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// RequestKey derives a request authentication key from a session key.
func RequestKey(sessionKey []byte) ([]byte, error) {
	return DeriveKey(sessionKey, LabelRequest)
}

// RequestMAC computes an HMAC-SHA256 over the canonical request message.
func RequestMAC(
	requestKey []byte,
	method, path string,
	counter uint64,
	body []byte,
) []byte {
	bodyHash := sha256.Sum256(body)

	message := make([]byte, 0, 4+len(method)+4+len(path)+8+sha256.Size)

	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(method)))
	message = append(message, length[:]...)
	message = append(message, method...)

	binary.BigEndian.PutUint32(length[:], uint32(len(path)))
	message = append(message, length[:]...)
	message = append(message, path...)

	var counterBytes [8]byte
	binary.BigEndian.PutUint64(counterBytes[:], counter)
	message = append(message, counterBytes[:]...)

	message = append(message, bodyHash[:]...)

	mac := hmac.New(sha256.New, requestKey)
	_, _ = mac.Write(message)

	return mac.Sum(nil)
}

// VerifyRequestMAC verifies a request MAC using constant-time comparison.
func VerifyRequestMAC(
	requestKey []byte,
	method, path string,
	counter uint64,
	body, mac []byte,
) bool {
	if len(mac) != sha256.Size {
		return false
	}

	expected := RequestMAC(requestKey, method, path, counter, body)
	return hmac.Equal(expected, mac)
}

// RecoveryCredentialID derives a 16-byte recovery credential ID from a user ID.
func RecoveryCredentialID(userID []byte) ([]byte, error) {
	if len(userID) != 16 {
		return nil, errors.New("invalid user ID")
	}

	h := sha256.New()
	_, _ = h.Write([]byte(LabelRecoveryCred))
	_, _ = h.Write(userID)

	return h.Sum(nil)[:16], nil
}
