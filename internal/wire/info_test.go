// File: internal/wire/info_test.go

package wire

import (
	"bytes"
	"testing"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
)

func TestToInfoRoundTrip(t *testing.T) {
	in := service.BlobInfo{Kind: 3, Version: 9, PrevHash: [32]byte{4, 5}, Data: []byte("data")}

	out, err := BlobFromInfo(in).ToInfo()
	if err != nil {
		t.Fatal(err)
	}

	if out.Kind != in.Kind || out.Version != in.Version ||
		out.PrevHash != in.PrevHash || !bytes.Equal(out.Data, in.Data) {
		t.Fatalf("round trip changed the blob: %+v", out)
	}
}

func TestToInfoRejectsWrongHashLength(t *testing.T) {
	for _, n := range []int{0, 31, 33} {
		if _, err := (Blob{PrevHash: make([]byte, n)}).ToInfo(); err == nil {
			t.Fatalf("a %d byte hash was accepted", n)
		}
	}
}
