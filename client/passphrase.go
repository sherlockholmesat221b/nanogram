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
	minPassphraseWords      = 8
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
		return "", errors.New("passphrase must contain at least 8 words")
	}

	wordList := bip39.GetWordList()
	if len(wordList) != 2048 {
		return "", errors.New("unexpected BIP39 word list size")
	}

	selected := make([]string, words)
	var randomBytes [2]byte

	for i := range selected {
		if _, err := cryptorand.Read(randomBytes[:]); err != nil {
			return "", err
		}

		index := binary.BigEndian.Uint16(randomBytes[:]) & bip39WordIndexMask
		selected[i] = wordList[index]
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

	return errors.New("passphrase must contain at least 8 distinct BIP39 words, or be a custom passphrase of at least 20 characters when custom passphrases are allowed")
}
