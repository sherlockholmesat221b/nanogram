package zkcrypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

const (
	goldenDeriveHex = "53eeba818a132975e337a0890341b0fc64b64bd4059c97d423dfe01fd3ea0a87"
	goldenBlobHex   = "010303030303030303030303030303030303030303030303032762427f493649f363c5d9f912d9859940c3458de133acdb"
)

func testKey() []byte {
	return bytes.Repeat([]byte{0x02}, 32)
}

func testUserID() []byte {
	return bytes.Repeat([]byte{0x04}, 16)
}

func testNonce() []byte {
	return bytes.Repeat([]byte{0x03}, 24)
}

func testPlaintext() []byte {
	return []byte("zkc test")
}

func testSeal(
	t *testing.T,
) ([]byte, [32]byte, []byte, []byte, [32]byte) {
	t.Helper()

	key := testKey()
	userID := testUserID()
	plaintext := testPlaintext()
	prev := ZeroHash

	blob, hash, err := SealBlob(
		key, plaintext, userID, KindKEK, 1, prev,
	)
	if err != nil {
		t.Fatalf("SealBlob: %v", err)
	}

	return blob, hash, key, userID, prev
}

func TestSealOpenRoundTrip(t *testing.T) {
	blob, hash, key, userID, prev := testSeal(t)

	got, err := OpenBlob(
		key, blob, userID, KindKEK, 1, prev,
	)
	if err != nil {
		t.Fatalf("OpenBlob: %v", err)
	}
	if !bytes.Equal(got, testPlaintext()) {
		t.Fatalf("plaintext mismatch: got %x, want %x",
			got, testPlaintext())
	}

	wantHash := BlobHash(userID, KindKEK, 1, prev, blob)
	if hash != wantHash {
		t.Fatalf("BlobHash mismatch: got %x, want %x",
			hash, wantHash)
	}
}

func TestOpenBlobRejectsMetadataChanges(t *testing.T) {
	blob, _, key, userID, prev := testSeal(t)

	tests := []struct {
		name    string
		key     []byte
		userID  []byte
		kind    BlobKind
		version uint64
		prev    [32]byte
	}{
		{
			name:    "key",
			key:     bytes.Repeat([]byte{0x05}, 32),
			userID:  userID,
			kind:    KindKEK,
			version: 1,
			prev:    prev,
		},
		{
			name:    "userID",
			key:     key,
			userID:  bytes.Repeat([]byte{0x05}, 16),
			kind:    KindKEK,
			version: 1,
			prev:    prev,
		},
		{
			name:    "kind",
			key:     key,
			userID:  userID,
			kind:    KindMEK,
			version: 1,
			prev:    prev,
		},
		{
			name:    "version",
			key:     key,
			userID:  userID,
			kind:    KindKEK,
			version: 2,
			prev:    prev,
		},
		{
			name:    "prev",
			key:     key,
			userID:  userID,
			kind:    KindKEK,
			version: 1,
			prev:    [32]byte{1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := OpenBlob(
				tt.key, blob, tt.userID,
				tt.kind, tt.version, tt.prev,
			)
			if err == nil {
				t.Fatal("OpenBlob unexpectedly succeeded")
			}
			if err.Error() != "blob rejected" {
				t.Fatalf("unexpected error: %q", err)
			}
		})
	}
}

func TestOpenBlobRejectsEverySingleByteFlip(t *testing.T) {
	blob, _, key, userID, prev := testSeal(t)

	for i := range blob {
		t.Run(hex.EncodeToString([]byte{
			byte(i >> 8), byte(i),
		}), func(t *testing.T) {
			modified := bytes.Clone(blob)
			modified[i] ^= 0x01

			_, err := OpenBlob(
				key, modified, userID, KindKEK, 1, prev,
			)
			if err == nil {
				t.Fatalf("OpenBlob accepted modified byte at index %d", i)
			}
			if err.Error() != "blob rejected" {
				t.Fatalf("unexpected error: %q", err)
			}
		})
	}
}

func TestOpenBlobRejectsTruncatedBlob(t *testing.T) {
	blob, _, key, userID, prev := testSeal(t)

	for _, length := range []int{
		0, 1, 24, 25, 39, 40, len(blob) - 1,
	} {
		if length < 0 || length >= len(blob) {
			continue
		}

		t.Run(hex.EncodeToString([]byte{
			byte(length >> 8), byte(length),
		}), func(t *testing.T) {
			_, err := OpenBlob(
				key, blob[:length], userID, KindKEK, 1, prev,
			)
			if err == nil {
				t.Fatalf("OpenBlob accepted truncated blob of length %d", length)
			}
			if err.Error() != "blob rejected" {
				t.Fatalf("unexpected error: %q", err)
			}
		})
	}
}

func TestOpenBlobRejectsInvalidFormat(t *testing.T) {
	blob, _, key, userID, prev := testSeal(t)
	blob[0] = 0x02

	_, err := OpenBlob(key, blob, userID, KindKEK, 1, prev)
	if err == nil {
		t.Fatal("OpenBlob accepted format version 2")
	}
	if err.Error() != "blob rejected" {
		t.Fatalf("unexpected error: %q", err)
	}
}

func TestSealBlobUsesRandomNonces(t *testing.T) {
	key := testKey()
	userID := testUserID()
	plaintext := testPlaintext()

	first, _, err := SealBlob(
		key, plaintext, userID, KindKEK, 1, ZeroHash,
	)
	if err != nil {
		t.Fatalf("first SealBlob: %v", err)
	}

	second, _, err := SealBlob(
		key, plaintext, userID, KindKEK, 1, ZeroHash,
	)
	if err != nil {
		t.Fatalf("second SealBlob: %v", err)
	}

	if bytes.Equal(first, second) {
		t.Fatal("two seals produced identical blobs")
	}
	if bytes.Equal(first[1:blobHeaderSize], second[1:blobHeaderSize]) {
		t.Fatal("two seals produced identical nonces")
	}
}

func TestBlobHashChangesWithMetadataAndBlob(t *testing.T) {
	blob, original, _, userID, prev := testSeal(t)

	tests := []struct {
		name    string
		userID  []byte
		kind    BlobKind
		version uint64
		prev    [32]byte
		blob    []byte
	}{
		{
			name:    "userID",
			userID:  bytes.Repeat([]byte{0x05}, 16),
			kind:    KindKEK,
			version: 1,
			prev:    prev,
			blob:    blob,
		},
		{
			name:    "kind",
			userID:  userID,
			kind:    KindMEK,
			version: 1,
			prev:    prev,
			blob:    blob,
		},
		{
			name:    "version",
			userID:  userID,
			kind:    KindKEK,
			version: 2,
			prev:    prev,
			blob:    blob,
		},
		{
			name:    "prev",
			userID:  userID,
			kind:    KindKEK,
			version: 1,
			prev:    [32]byte{1},
			blob:    blob,
		},
		{
			name:    "blob",
			userID:  userID,
			kind:    KindKEK,
			version: 1,
			prev:    prev,
			blob:    bytes.Clone(blob),
		},
	}

	tests[len(tests)-1].blob[len(tests[len(tests)-1].blob)-1] ^= 0x01

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BlobHash(
				tt.userID, tt.kind, tt.version, tt.prev, tt.blob,
			)
			if got == original {
				t.Fatal("hash did not change")
			}
		})
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	secret := bytes.Repeat([]byte{0x01}, 32)

	first, err := DeriveKey(secret, LabelWrap)
	if err != nil {
		t.Fatalf("first DeriveKey: %v", err)
	}

	second, err := DeriveKey(secret, LabelWrap)
	if err != nil {
		t.Fatalf("second DeriveKey: %v", err)
	}

	if !bytes.Equal(first, second) {
		t.Fatal("DeriveKey is not deterministic")
	}
	if len(first) != 32 {
		t.Fatalf("wrong key length: got %d, want 32", len(first))
	}
}

func TestDeriveKeyDifferentLabels(t *testing.T) {
	secret := bytes.Repeat([]byte{0x01}, 32)

	first, err := DeriveKey(secret, LabelWrap)
	if err != nil {
		t.Fatalf("DeriveKey(LabelWrap): %v", err)
	}

	second, err := DeriveKey(secret, LabelBlob)
	if err != nil {
		t.Fatalf("DeriveKey(LabelBlob): %v", err)
	}

	if bytes.Equal(first, second) {
		t.Fatal("different labels produced identical keys")
	}
}

func TestDeriveKeyRejectsShortSecret(t *testing.T) {
	_, err := DeriveKey(bytes.Repeat([]byte{0x01}, 31), LabelWrap)
	if err == nil {
		t.Fatal("DeriveKey accepted a 31-byte secret")
	}
}

func TestGoldenDeriveKey(t *testing.T) {
	secret := bytes.Repeat([]byte{0x01}, 32)

	got, err := DeriveKey(secret, LabelWrap)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}

	gotHex := hex.EncodeToString(got)
	if goldenDeriveHex == "TODO" {
		t.Fatalf("paste this into goldenDeriveHex: %s", gotHex)
	}
	if gotHex != goldenDeriveHex {
		t.Fatalf("DeriveKey golden mismatch: got %s, want %s",
			gotHex, goldenDeriveHex)
	}
}

func TestGoldenSealWithNonce(t *testing.T) {
	blob, _, err := sealWithNonce(
		testKey(),
		testPlaintext(),
		testUserID(),
		KindKEK,
		1,
		ZeroHash,
		testNonce(),
	)
	if err != nil {
		t.Fatalf("sealWithNonce: %v", err)
	}

	gotHex := hex.EncodeToString(blob)
	if goldenBlobHex == "TODO" {
		t.Fatalf("paste this into goldenBlobHex: %s", gotHex)
	}
	if gotHex != goldenBlobHex {
		t.Fatalf("blob golden mismatch: got %s, want %s",
			gotHex, goldenBlobHex)
	}
}

func TestOpenBlobUsesGenericError(t *testing.T) {
	_, err := OpenBlob(
		testKey(),
		[]byte{0x01},
		testUserID(),
		KindKEK,
		1,
		ZeroHash,
	)
	if !errors.Is(err, errBlobRejected) {
		t.Fatalf("expected generic blob rejection, got %v", err)
	}
}
