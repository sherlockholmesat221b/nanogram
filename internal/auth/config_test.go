package auth

import (
	"bytes"
	"testing"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/zkcrypto"
)

func TestNewConfiguration(t *testing.T) {
	first := NewConfiguration()
	second := NewConfiguration()

	if first.KDF != second.KDF {
		t.Error("KDF differs between configurations")
	}
	if first.MAC != second.MAC {
		t.Error("MAC differs between configurations")
	}
	if first.Hash != second.Hash {
		t.Error("Hash differs between configurations")
	}
	if first.KSF != second.KSF {
		t.Error("KSF differs between configurations")
	}
	if first.OPRF != second.OPRF {
		t.Error("OPRF differs between configurations")
	}
	if first.AKE != second.AKE {
		t.Error("AKE differs between configurations")
	}
	if !bytes.Equal(first.Context, second.Context) {
		t.Error("Context differs between configurations")
	}

	wantContext := []byte(zkcrypto.LabelOpaqueContext)
	if len(first.Context) == 0 {
		t.Fatal("Context must not be empty")
	}
	if !bytes.Equal(first.Context, wantContext) {
		t.Errorf("Context = %q, want %q", first.Context, wantContext)
	}
	if len(second.Context) == 0 {
		t.Fatal("second configuration's Context must not be empty")
	}
	if !bytes.Equal(second.Context, wantContext) {
		t.Errorf("second Context = %q, want %q", second.Context, wantContext)
	}
}
