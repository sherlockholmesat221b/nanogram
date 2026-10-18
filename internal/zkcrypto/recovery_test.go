// File: internal/zkcrypto/recovery_test.go

package zkcrypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestRecoveryKeyPhraseRoundTripRandom(t *testing.T) {
	for i := 0; i < 20; i++ {
		key, err := NewRecoveryKey()
		if err != nil {
			t.Fatalf("NewRecoveryKey: %v", err)
		}
		if len(key) != 32 {
			t.Fatalf("NewRecoveryKey length = %d, want 32", len(key))
		}
		phrase, err := RecoveryPhrase(key)
		if err != nil {
			t.Fatalf("RecoveryPhrase: %v", err)
		}
		got, err := RecoveryKeyFromPhrase(phrase)
		if err != nil {
			t.Fatalf("RecoveryKeyFromPhrase: %v", err)
		}
		if !bytes.Equal(got, key) {
			t.Fatalf("round trip mismatch: got %x, want %x", got, key)
		}
	}
}

func TestRecoveryPhraseAllZeroKey(t *testing.T) {
	key := make([]byte, 32)
	phrase, err := RecoveryPhrase(key)
	if err != nil {
		t.Fatalf("RecoveryPhrase: %v", err)
	}
	want := strings.TrimSpace(strings.Repeat("abandon ", 23) + "art")
	if phrase != want {
		t.Fatalf("RecoveryPhrase(zero key) = %q, want %q", phrase, want)
	}
}

func TestRecoveryPhraseRejectsWrongKeyLength(t *testing.T) {
	for _, key := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		if _, err := RecoveryPhrase(key); err == nil {
			t.Fatalf("RecoveryPhrase accepted key length %d", len(key))
		}
	}
}

func TestRecoveryKeyFromPhraseNormalizesInput(t *testing.T) {
	key := make([]byte, 32)
	phrase, err := RecoveryPhrase(key)
	if err != nil {
		t.Fatalf("RecoveryPhrase: %v", err)
	}
	phrase = "  " + strings.ToUpper(strings.ReplaceAll(phrase, " ", "   ")) + "  \n"
	got, err := RecoveryKeyFromPhrase(phrase)
	if err != nil {
		t.Fatalf("RecoveryKeyFromPhrase rejected normalized phrase: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("normalized phrase decoded to %x, want %x", got, key)
	}
}

func TestRecoveryKeyFromPhraseRejectsInvalidPhrases(t *testing.T) {
	valid := strings.TrimSpace(strings.Repeat("abandon ", 23) + "art")
	tooFew := strings.Join(strings.Fields(valid)[:23], " ")
	tooMany := valid + " abandon"
	// Replacing the final word "art" with the valid BIP39 word "zoo"
	// makes the checksum invalid for this entropy.
	replacedWord := strings.TrimSuffix(valid, "art") + "zoo"
	nonListWord := strings.TrimSuffix(valid, "art") + "notaword"

	for name, phrase := range map[string]string{
		"23 words":              tooFew,
		"25 words":              tooMany,
		"checksum (art to zoo)": replacedWord,
		"non-list word":         nonListWord,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := RecoveryKeyFromPhrase(phrase)
			if err == nil {
				t.Fatal("RecoveryKeyFromPhrase unexpectedly succeeded")
			}
			if err.Error() != errInvalidRecoveryPhrase.Error() {
				t.Fatalf("error = %q, want generic error %q", err, errInvalidRecoveryPhrase)
			}
		})
	}
}

func TestRecoveryKeyFromOfficialBIP39Vectors(t *testing.T) {
	tests := []struct {
		name    string
		entropy string
		phrase  string
	}{
		{
			name:    "all zero entropy",
			entropy: "0000000000000000000000000000000000000000000000000000000000000000",
			phrase:  strings.TrimSpace(strings.Repeat("abandon ", 23) + "art"),
		},
		{
			name:    "7f entropy",
			entropy: "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
			phrase:  "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want, err := hex.DecodeString(tt.entropy)
			if err != nil {
				t.Fatal(err)
			}
			got, err := RecoveryKeyFromPhrase(tt.phrase)
			if err != nil {
				t.Fatalf("RecoveryKeyFromPhrase: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("entropy = %x, want %x", got, want)
			}
			gotPhrase, err := RecoveryPhrase(want)
			if err != nil {
				t.Fatalf("RecoveryPhrase: %v", err)
			}
			if gotPhrase != tt.phrase {
				t.Fatalf("mnemonic = %q, want %q", gotPhrase, tt.phrase)
			}
		})
	}
}

func TestRecoveryDerivedKeysAreDistinct(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	login, err := RecoveryLoginSecret(key)
	if err != nil {
		t.Fatalf("RecoveryLoginSecret: %v", err)
	}
	wrap, err := RecoveryWrapKey(key)
	if err != nil {
		t.Fatalf("RecoveryWrapKey: %v", err)
	}
	if bytes.Equal(login, wrap) {
		t.Fatal("recovery login and wrapping keys are equal")
	}
	if bytes.Equal(login, key) {
		t.Fatal("recovery login key equals raw key")
	}
	if bytes.Equal(wrap, key) {
		t.Fatal("recovery wrapping key equals raw key")
	}
}
