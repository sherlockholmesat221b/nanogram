// File: client/passphrase_test.go

package client

import (
	"strings"
	"testing"

	"github.com/tyler-smith/go-bip39"
)

func TestGeneratePassphrase(t *testing.T) {
	for _, words := range []int{6, DefaultPassphraseWords, 12} {
		passphrase, err := GeneratePassphrase(words)
		if err != nil {
			t.Fatalf("GeneratePassphrase(%d): %v", words, err)
		}

		if got := len(strings.Fields(passphrase)); got != words {
			t.Fatalf("GeneratePassphrase(%d) made %d words", words, got)
		}
		if err := CheckPassword(passphrase, nil); err != nil {
			t.Fatalf("a suggestion was refused: %v", err)
		}
	}
}

func TestGeneratePassphraseLimits(t *testing.T) {
	for _, words := range []int{0, 5, 65} {
		if passphrase, err := GeneratePassphrase(words); err == nil || passphrase != "" {
			t.Fatalf("GeneratePassphrase(%d) = %q, %v", words, passphrase, err)
		}
	}
}

func TestGeneratedPassphrasesNeverRepeatAWord(t *testing.T) {
	for _, words := range []int{6, DefaultPassphraseWords, 12} {
		for i := 0; i < 200; i++ {
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
		}
	}
}

func TestGeneratedPassphrasesDiffer(t *testing.T) {
	first, err := GeneratePassphrase(12)
	if err != nil {
		t.Fatal(err)
	}
	second, err := GeneratePassphrase(12)
	if err != nil {
		t.Fatal(err)
	}

	if first == second {
		t.Fatal("two generated passphrases are identical")
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
		{"five words are not a word passphrase", "Abandon ability able about above", "Abandon ability able about above"},
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
