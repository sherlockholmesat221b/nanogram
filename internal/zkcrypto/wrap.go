// File: internal/zkcrypto/wrap.go

package zkcrypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// BlobKind identifies the purpose of an encrypted blob.
type BlobKind byte

const (
	// KindKEK identifies a key-encryption-key blob.
	KindKEK BlobKind = 1
	// KindMEK identifies a message-encryption-key blob.
	KindMEK BlobKind = 2
	// KindIdentity identifies an identity blob.
	KindIdentity BlobKind = 3
	// KindRecovery identifies a recovery blob.
	KindRecovery BlobKind = 4
)

const (
	blobFormatVersion = byte(0x01)
	blobNonceSize     = chacha20poly1305.NonceSizeX
	blobTagSize       = chacha20poly1305.Overhead
	blobHeaderSize    = 1 + blobNonceSize
	blobMinSize       = blobHeaderSize + blobTagSize
	blobKeySize       = chacha20poly1305.KeySize
	blobUserIDSize    = 16
	blobVersionSize   = 8
	blobPrevHashSize  = 32
)

var (
	// ZeroHash is the all-zero hash used when no previous blob exists.
	ZeroHash [32]byte

	errBlobRejected = errors.New("blob rejected")
)

// DeriveKey derives a 32-byte key from a secret and a domain-separation label.
func DeriveKey(secret []byte, label string) ([]byte, error) {
	if len(secret) < 32 {
		return nil, errors.New("secret must be at least 32 bytes")
	}

	out := make([]byte, blobKeySize)
	r := hkdf.New(sha256.New, secret, nil, []byte(label))

	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}

	return out, nil
}

// blobAAD constructs the authenticated metadata:
//
//	LabelBlob || userID || kind || version || prev
//
// An invalid user ID produces nil. Callers that require valid metadata
// must reject a nil result.
func blobAAD(
	userID []byte,
	kind BlobKind,
	version uint64,
	prev [32]byte,
) []byte {
	if len(userID) != blobUserIDSize {
		return nil
	}

	aad := make([]byte, 0, len(LabelBlob)+blobUserIDSize+1+
		blobVersionSize+blobPrevHashSize)

	aad = append(aad, []byte(LabelBlob)...)
	aad = append(aad, userID...)
	aad = append(aad, byte(kind))

	var versionBytes [blobVersionSize]byte
	binary.BigEndian.PutUint64(versionBytes[:], version)
	aad = append(aad, versionBytes[:]...)
	aad = append(aad, prev[:]...)

	return aad
}

// SealBlob encrypts plaintext and returns the encoded blob and its hash.
func SealBlob(
	key, plaintext, userID []byte,
	kind BlobKind,
	version uint64,
	prev [32]byte,
) (blob []byte, hash [32]byte, err error) {
	if len(userID) != blobUserIDSize {
		return nil, ZeroHash, errors.New("invalid user ID")
	}

	nonce := make([]byte, blobNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, ZeroHash, err
	}

	return sealWithNonce(
		key, plaintext, userID, kind, version, prev, nonce,
	)
}

// sealWithNonce seals a blob using the supplied nonce.
// It is unexported so callers cannot accidentally bypass random nonce
// generation through the public SealBlob API.
func sealWithNonce(
	key, plaintext, userID []byte,
	kind BlobKind,
	version uint64,
	prev [32]byte,
	nonce []byte,
) (blob []byte, hash [32]byte, err error) {
	if len(userID) != blobUserIDSize {
		return nil, ZeroHash, errors.New("invalid user ID")
	}
	if len(nonce) != blobNonceSize {
		return nil, ZeroHash, errors.New("invalid nonce length")
	}

	aad := blobAAD(userID, kind, version, prev)
	if aad == nil {
		return nil, ZeroHash, errors.New("invalid associated data")
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, ZeroHash, err
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, aad)

	blob = make([]byte, 0, blobHeaderSize+len(ciphertext))
	blob = append(blob, blobFormatVersion)
	blob = append(blob, nonce...)
	blob = append(blob, ciphertext...)

	hash, err = BlobHash(userID, kind, version, prev, blob)
	if err != nil {
		return nil, ZeroHash, err
	}

	return blob, hash, nil
}

// OpenBlob authenticates and decrypts a blob using its associated metadata.
func OpenBlob(
	key, blob, userID []byte,
	kind BlobKind,
	version uint64,
	prev [32]byte,
) ([]byte, error) {
	reject := func() ([]byte, error) {
		return nil, errBlobRejected
	}

	if len(userID) != blobUserIDSize {
		return reject()
	}
	if len(blob) < blobMinSize {
		return reject()
	}
	if blob[0] != blobFormatVersion {
		return reject()
	}

	aad := blobAAD(userID, kind, version, prev)
	if aad == nil {
		return reject()
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return reject()
	}

	nonce := blob[1:blobHeaderSize]
	ciphertext := blob[blobHeaderSize:]

	plaintext, err := aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return reject()
	}

	return plaintext, nil
}

// BlobHash computes the SHA-256 hash of a blob's authenticated metadata
// followed by the encoded blob. It returns an error if userID is not 16 bytes.
func BlobHash(
	userID []byte,
	kind BlobKind,
	version uint64,
	prev [32]byte,
	blob []byte,
) ([32]byte, error) {
	aad := blobAAD(userID, kind, version, prev)
	if aad == nil {
		return ZeroHash, errors.New("invalid user ID")
	}

	h := sha256.New()
	_, _ = h.Write(aad)
	_, _ = h.Write(blob)

	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}
