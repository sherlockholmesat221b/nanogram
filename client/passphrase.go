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

// CheckPassphrase checks the passphrase format only; it cannot prove that the words were chosen at random. User interfaces must only offer output from GeneratePassphrase.
func CheckPassphrase(p string, allowCustom bool) error {
	normalised := strings.Join(
		strings.Fields(strings.ToLower(p)),
		" ",
	)

	words := strings.Fields(normalised)
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
	if allowCustom && utf8.RuneCountInString(normalised) >= minCustomPassphraseSize {
		return nil
	}

	return errors.New("passphrase must contain at least 6 distinct BIP39 words, or be a custom passphrase of at least 20 characters when custom passphrases are allowed")
}
