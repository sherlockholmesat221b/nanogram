package zkcrypto

import (
	"encoding/hex"
	"testing"

	"github.com/bytemare/ksf"
)

const goldenHex = "efb51f9a76584f6dd6a4f7942a1a2f6ae5a6e4ec5142ff674dfd5d27eb45e446"

func TestArgon2idGolden(t *testing.T) {
	got := ksf.Argon2id.Harden(
		[]byte("correct horse battery staple"),
		[]byte("0123456789abcdef"),
		32,
	)

	gotHex := hex.EncodeToString(got)
	if gotHex != goldenHex {
		t.Fatalf("Argon2id golden mismatch: got %q; set goldenHex to this value", gotHex)
	}
}
