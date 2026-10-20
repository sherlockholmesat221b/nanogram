// File: client/passphrase.go

package client

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/tyler-smith/go-bip39"
)

const (
	// DefaultPassphraseWords is the length user interfaces should generate:
	// 7 words from a list of 2048 are about 77 bits.
	DefaultPassphraseWords = 7

	minPassphraseWords      = 6
	maxPassphraseWords      = 64
	minCustomPassphraseSize = 20
	bip39WordIndexMask      = 0x07ff
)

var bip39Words = func() map[string]struct{} {
	words := bip39.GetWordList()
	result := make(map[string]struct{}, len(words))

	for _, word := range words {
		result[word] = struct{}{}
	}

	return result
}()

// GeneratePassphrase generates a passphrase containing the requested number of randomly selected BIP39 words.
func GeneratePassphrase(words int) (string, error) {
	if words < minPassphraseWords {
		return "", errors.New("passphrase must contain at least 6 words")
	}

	if words > maxPassphraseWords {
		return "", errors.New("passphrase must contain at most 64 words")
	}

	wordList := bip39.GetWordList()
	if len(wordList) != 2048 {
		return "", errors.New("unexpected BIP39 word list size")
	}

	selected := make([]string, 0, words)
	used := make(map[uint16]struct{}, words)
	var randomBytes [2]byte

	// Words are drawn without repeats, so the check that asks for distinct
	// words can never refuse a generated passphrase.
	for len(selected) < words {
		if _, err := cryptorand.Read(randomBytes[:]); err != nil {
			return "", err
		}

		index := binary.BigEndian.Uint16(randomBytes[:]) & bip39WordIndexMask
		if _, repeated := used[index]; repeated {
			continue
		}

		used[index] = struct{}{}
		selected = append(selected, wordList[index])
	}

	return strings.Join(selected, " "), nil
}

// PasswordInput returns the string that goes into OPAQUE for what the user
// typed. It is the typed text exactly, with one convenience: when the text is
// made only of words from the BIP39 list (at least the minimum number of
// them) the lowercase, single-spaced form is used, so capitals and spacing do
// not matter for a generated passphrase. Anything else, such as a password from
// a password manager, is used exactly as typed. Registration and login both
// use this function, and the server never sees either form.
func PasswordInput(p string) string {
	words := strings.Fields(strings.ToLower(p))

	if len(words) >= minPassphraseWords {
		allListed := true

		for _, word := range words {
			if _, ok := bip39Words[word]; !ok {
				allListed = false
				break
			}
		}

		if allListed {
			return strings.Join(words, " ")
		}
	}

	return p
}

// CheckPassphrase checks the passphrase format only; it cannot prove that the words were chosen at random. User interfaces must only offer output from GeneratePassphrase.
func CheckPassphrase(p string, allowCustom bool) error {
	words := strings.Fields(strings.ToLower(p))
	if len(words) >= minPassphraseWords {
		distinct := make(map[string]struct{}, len(words))
		allValid := true

		for _, word := range words {
			if _, ok := bip39Words[word]; !ok {
				allValid = false
				break
			}

			distinct[word] = struct{}{}
		}

		if allValid && len(distinct) >= minPassphraseWords {
			return nil
		}
	}

	// allowCustom is only a length check; it is weak and must be false in shipped user interfaces.
	if allowCustom && utf8.RuneCountInString(p) >= minCustomPassphraseSize {
		return nil
	}

	return errors.New("passphrase must contain at least 6 distinct BIP39 words, or be a custom passphrase of at least 20 characters when custom passphrases are allowed")
}
