// File: client/passphrase.go

package client

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/tyler-smith/go-bip39"
)

const (
	// DefaultPassphraseWords is the length suggested to users: 7 words from a
	// list of 2048 are about 77 bits.
	DefaultPassphraseWords = 7

	minPassphraseWords = 6
	maxPassphraseWords = 64
	bip39WordIndexMask = 0x07ff

	// A suggestion that the strength check would refuse is thrown away and
	// drawn again. That costs a fraction of a bit.
	maxSuggestionTries = 100
)

var bip39Words = func() map[string]struct{} {
	words := bip39.GetWordList()
	result := make(map[string]struct{}, len(words))

	for _, word := range words {
		result[word] = struct{}{}
	}

	return result
}()

// drawWords picks words from the BIP39 list without repeating one.
func drawWords(words int) (string, error) {
	wordList := bip39.GetWordList()
	if len(wordList) != 2048 {
		return "", errors.New("unexpected BIP39 word list size")
	}

	selected := make([]string, 0, words)
	used := make(map[uint16]struct{}, words)
	var randomBytes [2]byte

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

// GeneratePassphrase suggests a passphrase of random BIP39 words. It never
// returns one that CheckPassword would refuse. Using it is optional: users may
// choose their own password.
func GeneratePassphrase(words int) (string, error) {
	if words < minPassphraseWords {
		return "", errors.New("passphrase must contain at least 6 words")
	}
	if words > maxPassphraseWords {
		return "", errors.New("passphrase must contain at most 64 words")
	}

	for try := 0; try < maxSuggestionTries; try++ {
		passphrase, err := drawWords(words)
		if err != nil {
			return "", err
		}

		if CheckPassword(passphrase, nil) == nil {
			return passphrase, nil
		}
	}

	return "", errors.New("could not make a passphrase that passes the strength check")
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
