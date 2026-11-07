// File: client/strength.go

package client

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/trustelem/zxcvbn"
)

const (
	// MinGuessBits is the least number of guesses, as a power of two, that an
	// attacker must need for a password to be accepted. The estimate comes from
	// zxcvbn, which knows common words, names, keyboard patterns, dates and
	// substitutions, so "Tr0ub4dor&3" counts as the weak password it is.
	MinGuessBits = 66.0

	maxPasswordBytes = 1024

	// zxcvbn gets slow on very long input, so only the start is judged. The
	// start of a password is never harder to guess than the whole, so this
	// errs on the safe side.
	estimateRunes = 100
)

// separators are what people put between words. zxcvbn charges for each one
// as if it were a random character, which makes "word word word word" look
// about 20 bits stronger than it is, because an attacker just tries the usual
// separators. So the estimate is also made with them removed, and the lower of
// the two counts.
const separators = " \t-_.,"

func squash(password string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune(separators, r) {
			return -1
		}

		return r
	}, password)
}

func estimate(password string, userInputs []string) float64 {
	if utf8.RuneCountInString(password) > estimateRunes {
		password = string([]rune(password)[:estimateRunes])
	}

	guesses := zxcvbn.PasswordStrength(password, userInputs).Guesses

	switch {
	case guesses < 1:
		return 0
	case math.IsInf(guesses, 1) || math.IsNaN(guesses):
		return math.MaxFloat64
	}

	return math.Log2(guesses)
}

// GuessBits estimates how many guesses an attacker needs for the password, as
// a power of two. userInputs are words the attacker is likely to try first,
// such as the username.
func GuessBits(password string, userInputs []string) float64 {
	bits := estimate(password, userInputs)

	if squashed := squash(password); squashed != "" && squashed != password {
		if other := estimate(squashed, userInputs); other < bits {
			bits = other
		}
	}

	return bits
}

// CheckPassword refuses a password that is too easy to guess. It judges what
// goes into OPAQUE (see PasswordInput). It only advises: the server never sees
// the password and cannot enforce anything, so another client may skip it, and
// then only its own users are weaker.
func CheckPassword(password string, userInputs []string) error {
	if password == "" {
		return errors.New("the password is empty")
	}
	if len(password) > maxPasswordBytes {
		return fmt.Errorf("the password is longer than %d bytes", maxPasswordBytes)
	}

	bits := GuessBits(PasswordInput(password), userInputs)
	if bits < MinGuessBits {
		return fmt.Errorf(
			"the password is too easy to guess (about %.0f bits, at least %.0f needed): use more characters or more unrelated words, or let a password manager make one",
			bits, MinGuessBits,
		)
	}

	return nil
}
