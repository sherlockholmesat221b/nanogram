// File: client/passphrase_test.go

package client

import (
	"strings"
	"testing"

	"github.com/tyler-smith/go-bip39"
)

func TestGeneratePassphrase(t *testing.T) {
	tests := []struct {
		name  string
		words int
	}{
		{
			name:  "8 words",
			words: 8,
		},
		{
			name:  "12 words",
			words: 12,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			passphrase, err := GeneratePassphrase(tt.words)
			if err != nil {
				t.Fatalf("GeneratePassphrase(%d) error = %v", tt.words, err)
			}

			words := strings.Fields(passphrase)
			if len(words) != tt.words {
				t.Fatalf(
					"GeneratePassphrase(%d) produced %d words, want %d",
					tt.words,
					len(words),
					tt.words,
				)
			}

			if err := CheckPassphrase(passphrase, false); err != nil {
				t.Fatalf("CheckPassphrase(generated passphrase, false) error = %v", err)
			}
		})
	}
}

func TestGeneratePassphraseRejectsTooFewWords(t *testing.T) {
	passphrase, err := GeneratePassphrase(7)
	if err == nil {
		t.Fatal("GeneratePassphrase(7) error = nil, want error")
	}

	if passphrase != "" {
		t.Fatalf("GeneratePassphrase(7) = %q, want empty string", passphrase)
	}
}

func TestCheckPassphraseRejectsSevenWords(t *testing.T) {
	wordList := bip39.GetWordList()
	passphrase := strings.Join(wordList[:7], " ")

	if err := CheckPassphrase(passphrase, false); err == nil {
		t.Fatal("CheckPassphrase(7 words, false) error = nil, want error")
	}
}

func TestCheckPassphraseRejectsEightCopiesOfOneWord(t *testing.T) {
	passphrase := strings.TrimSpace(strings.Repeat("abandon ", 8))

	if err := CheckPassphrase(passphrase, false); err == nil {
		t.Fatal("CheckPassphrase(8 repeated words, false) error = nil, want error")
	}
}

func TestCheckPassphraseRejectsNineWordsWithSevenDistinctWords(t *testing.T) {
	wordList := bip39.GetWordList()
	words := append([]string(nil), wordList[:7]...)
	words = append(words, wordList[0], wordList[1])
	passphrase := strings.Join(words, " ")

	if err := CheckPassphrase(passphrase, false); err == nil {
		t.Fatal("CheckPassphrase(9 words with 7 distinct words, false) error = nil, want error")
	}
}

func TestCheckPassphraseAcceptsEightDistinctWords(t *testing.T) {
	wordList := bip39.GetWordList()
	passphrase := strings.Join(wordList[:8], " ")

	if err := CheckPassphrase(passphrase, false); err != nil {
		t.Fatalf("CheckPassphrase(8 distinct words, false) error = %v", err)
	}
}

func TestCheckPassphraseUnknownWord(t *testing.T) {
	passphrase := "abandon ability able about above absent absorb abstract definitelynotabip39word"

	if _, ok := bip39Words["definitelynotabip39word"]; ok {
		t.Fatal("test fixture unexpectedly exists in the BIP39 word list")
	}

	if err := CheckPassphrase(passphrase, false); err == nil {
		t.Fatal("CheckPassphrase(unknown word, false) error = nil, want error")
	}

	if err := CheckPassphrase(passphrase, true); err != nil {
		t.Fatalf("CheckPassphrase(long custom passphrase, true) error = %v", err)
	}
}

func TestCheckPassphraseAllowsLongCustomPassphrase(t *testing.T) {
	passphrase := "this contains an unknown word and is long enough"

	if err := CheckPassphrase(passphrase, false); err == nil {
		t.Fatal("CheckPassphrase(custom passphrase, false) error = nil, want error")
	}

	if err := CheckPassphrase(passphrase, true); err != nil {
		t.Fatalf("CheckPassphrase(custom passphrase, true) error = %v", err)
	}
}

func TestCheckPassphraseNormalisesWhitespaceAndCapitalisation(t *testing.T) {
	wordList := bip39.GetWordList()
	passphrase := strings.ToUpper(
		strings.Join(wordList[:8], " "),
	)

	passphrase = "  \t" + passphrase + "\n  "

	if err := CheckPassphrase(passphrase, false); err != nil {
		t.Fatalf("CheckPassphrase(normalisable passphrase, false) error = %v", err)
	}
}

func TestGeneratePassphraseProducesDifferentResults(t *testing.T) {
	first, err := GeneratePassphrase(12)
	if err != nil {
		t.Fatalf("first GeneratePassphrase(12) error = %v", err)
	}

	second, err := GeneratePassphrase(12)
	if err != nil {
		t.Fatalf("second GeneratePassphrase(12) error = %v", err)
	}

	if first == second {
		t.Fatal("two generated passphrases are identical")
	}
}

func TestCheckPassphraseNormalisesCustomPassphrase(t *testing.T) {
	passphrase := "  THIS   is\t a\n custom   passphrase  "

	if err := CheckPassphrase(passphrase, true); err != nil {
		t.Fatalf("CheckPassphrase(normalised custom passphrase, true) error = %v", err)
	}
}

func TestCheckPassphraseRejectsShortCustomPassphrase(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
	}{
		{
			name:       "19 characters",
			passphrase: "abcdefghijklmnopqrs",
		},
		{
			name:       "empty",
			passphrase: "",
		},
		{
			name:       "whitespace only",
			passphrase: " \t\n ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := CheckPassphrase(tt.passphrase, true); err == nil {
				t.Fatal("CheckPassphrase() error = nil, want error")
			}
		})
	}
}
