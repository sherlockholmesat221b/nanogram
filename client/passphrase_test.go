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
			name:  "6 words",
			words: 6,
		},
		{
			name:  "7 words",
			words: 7,
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
	passphrase, err := GeneratePassphrase(5)
	if err == nil {
		t.Fatal("GeneratePassphrase(5) error = nil, want error")
	}

	if passphrase != "" {
		t.Fatalf("GeneratePassphrase(5) = %q, want empty string", passphrase)
	}
}

func TestCheckPassphraseRejectsFiveWords(t *testing.T) {
	wordList := bip39.GetWordList()
	passphrase := strings.Join(wordList[:5], " ")

	if err := CheckPassphrase(passphrase, false); err == nil {
		t.Fatal("CheckPassphrase(5 words, false) error = nil, want error")
	}
}

func TestCheckPassphraseRejectsEightCopiesOfOneWord(t *testing.T) {
	passphrase := strings.TrimSpace(strings.Repeat("abandon ", 8))

	if err := CheckPassphrase(passphrase, false); err == nil {
		t.Fatal("CheckPassphrase(8 repeated words, false) error = nil, want error")
	}
}

func TestCheckPassphraseRejectsNineWordsWithFiveDistinctWords(t *testing.T) {
	wordList := bip39.GetWordList()
	words := append([]string(nil), wordList[:5]...)
	words = append(words, wordList[0], wordList[1], wordList[2], wordList[3])
	passphrase := strings.Join(words, " ")

	if err := CheckPassphrase(passphrase, false); err == nil {
		t.Fatal("CheckPassphrase(9 words with 5 distinct words, false) error = nil, want error")
	}
}

func TestCheckPassphraseAcceptsSixDistinctWords(t *testing.T) {
	wordList := bip39.GetWordList()
	passphrase := strings.Join(wordList[:6], " ")

	if err := CheckPassphrase(passphrase, false); err != nil {
		t.Fatalf("CheckPassphrase(6 distinct words, false) error = %v", err)
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

func TestGeneratedPassphrasesNeverRepeatAWord(t *testing.T) {
	for _, words := range []int{6, DefaultPassphraseWords, 12} {
		for i := 0; i < 500; i++ {
			passphrase, err := GeneratePassphrase(words)
			if err != nil {
				t.Fatalf("GeneratePassphrase(%d): %v", words, err)
			}

			seen := make(map[string]struct{}, words)
			for _, word := range strings.Fields(passphrase) {
				if _, repeated := seen[word]; repeated {
					t.Fatalf("%q repeats the word %q", passphrase, word)
				}
				seen[word] = struct{}{}
			}

			if err := CheckPassphrase(passphrase, false); err != nil {
				t.Fatalf("CheckPassphrase(%q): %v", passphrase, err)
			}
		}
	}
}

func TestDefaultPassphraseLength(t *testing.T) {
	passphrase, err := GeneratePassphrase(DefaultPassphraseWords)
	if err != nil {
		t.Fatal(err)
	}

	if got := len(strings.Fields(passphrase)); got != 7 {
		t.Fatalf("default passphrase has %d words, want 7", got)
	}
}

func TestGeneratePassphraseRejectsTooManyWords(t *testing.T) {
	if _, err := GeneratePassphrase(65); err == nil {
		t.Fatal("GeneratePassphrase(65) error = nil, want error")
	}
}

func TestPasswordInput(t *testing.T) {
	wordList := bip39.GetWordList()
	words := strings.Join(wordList[:6], " ")

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"words are canonicalised", "  " + strings.ToUpper(words) + "\t", words},
		{"words with odd spacing", strings.ReplaceAll(words, " ", "   "), words},
		{"a manager password is kept exactly", "Horses-BATTERYstaples ", "Horses-BATTERYstaples "},
		{"case and punctuation stay", "  Foo\tBAR \n baz  ", "  Foo\tBAR \n baz  "},
		{"five words are not a generated passphrase", "Abandon ability able about above", "Abandon ability able about above"},
		{"words and something else", words + " Hunter2", words + " Hunter2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PasswordInput(tt.input); got != tt.want {
				t.Fatalf("PasswordInput(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
