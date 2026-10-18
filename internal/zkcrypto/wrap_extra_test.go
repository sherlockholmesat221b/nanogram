package zkcrypto

import (
	"bytes"
	"math"
	"testing"
)

func TestSealOpenRejectsInvalidKeyLength(dt *testing.T) {
	key31 := bytes.Repeat([]byte{0x02}, 31)
	key33 := bytes.Repeat([]byte{0x02}, 33)
	var keyNil []byte

	userID := testUserID()
	plaintext := testPlaintext()
	prev := ZeroHash

	for _, k := range [][]byte{key31, key33, keyNil} {
		_, _, err := SealBlob(k, plaintext, userID, KindKEK, 1, prev)
		if err == nil {
			dt.Fatalf("SealBlob accepted key of length %d", len(k))
		}

		_, err = OpenBlob(k, make([]byte, blobMinSize), userID, KindKEK, 1, prev)
		if err == nil {
			dt.Fatalf("OpenBlob accepted key of length %d", len(k))
		}
	}
}

func TestSealOpenRejectsInvalidUserIDLength(dt *testing.T) {
	uid15 := bytes.Repeat([]byte{0x04}, 15)
	uid17 := bytes.Repeat([]byte{0x04}, 17)
	var uidNil []byte

	key := testKey()
	plaintext := testPlaintext()
	prev := ZeroHash

	for _, uid := range [][]byte{uid15, uid17, uidNil} {
		_, _, err := SealBlob(key, plaintext, uid, KindKEK, 1, prev)
		if err == nil {
			dt.Fatalf("SealBlob accepted userID of length %d", len(uid))
		}

		_, err = OpenBlob(key, make([]byte, blobMinSize), uid, KindKEK, 1, prev)
		if err == nil {
			dt.Fatalf("OpenBlob accepted userID of length %d", len(uid))
		}
	}
}

func TestEmptyPlaintextRoundTrip(dt *testing.T) {
	key := testKey()
	userID := testUserID()
	plaintext := []byte{}
	prev := ZeroHash

	blob, _, err := SealBlob(key, plaintext, userID, KindKEK, 1, prev)
	if err != nil {
		dt.Fatalf("SealBlob with empty plaintext: %v", err)
	}

	if len(blob) != 41 {
		dt.Fatalf("expected blob length exactly 41 for empty plaintext, got %d", len(blob))
	}

	got, err := OpenBlob(key, blob, userID, KindKEK, 1, prev)
	if err != nil {
		dt.Fatalf("OpenBlob with empty plaintext blob: %v", err)
	}

	if len(got) != 0 {
		dt.Fatalf("expected empty plaintext back, got length %d", len(got))
	}
}

func Test1MiBPlaintextRoundTrip(dt *testing.T) {
	key := testKey()
	userID := testUserID()
	plaintext := bytes.Repeat([]byte{0xAB}, 1024*1024)
	prev := ZeroHash

	blob, _, err := SealBlob(key, plaintext, userID, KindKEK, 1, prev)
	if err != nil {
		dt.Fatalf("SealBlob with 1 MiB plaintext: %v", err)
	}

	got, err := OpenBlob(key, blob, userID, KindKEK, 1, prev)
	if err != nil {
		dt.Fatalf("OpenBlob with 1 MiB plaintext blob: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		dt.Fatalf("1 MiB plaintext round trip mismatch")
	}
}

func TestOpenBlobNilAndEmptyBlob(dt *testing.T) {
	key := testKey()
	userID := testUserID()
	prev := ZeroHash

	for _, b := range [][]byte{nil, {}} {
		_, err := OpenBlob(key, b, userID, KindKEK, 1, prev)
		if err == nil {
			dt.Fatalf("OpenBlob accepted nil or empty blob")
		}
		if err.Error() != "blob rejected" {
			dt.Fatalf("unexpected error for nil/empty blob: %q", err)
		}
	}
}

func TestSealOpenVersionZeroAndMaxUint64(dt *testing.T) {
	key := testKey()
	userID := testUserID()
	plaintext := testPlaintext()
	prev := ZeroHash

	for _, ver := range []uint64{0, math.MaxUint64} {
		blob, _, err := SealBlob(key, plaintext, userID, KindKEK, ver, prev)
		if err != nil {
			dt.Fatalf("SealBlob with version %d: %v", ver, err)
		}

		got, err := OpenBlob(key, blob, userID, KindKEK, ver, prev)
		if err != nil {
			dt.Fatalf("OpenBlob with version %d: %v", ver, err)
		}

		if !bytes.Equal(got, plaintext) {
			dt.Fatalf("plaintext mismatch for version %d", ver)
		}
	}
}
