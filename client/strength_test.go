// File: client/strength_test.go

package client

import (
	"strings"
	"testing"
)

func TestCheckPasswordRefusesWeakPasswords(t *testing.T) {
	weak := []string{
		"",
		"password",
		"Password1!",
		"letmein",
		"qwertyuiop",
		"12345678901234567890",
		"aaaaaaaaaaaaaaaaaaaa",
		"Tr0ub4dor&3",
		"correct horse battery staple",
		"correct-horse-battery-staple",
		"correct_horse_battery_staple",
		"love love love love love love",
		"abcdefghijklmnopqrstuvwxyz",
	}

	for _, password := range weak {
		if err := CheckPassword(password, nil); err == nil {
			t.Fatalf("%q was accepted (about %.0f bits)", password, GuessBits(password, nil))
		}
	}
}

func TestCheckPasswordAcceptsStrongPasswords(t *testing.T) {
	strong := []string{
		"k9#Vq2$Lm8@xW4!zR7pT",
		"Zm4tR9pLw2xQ7vBn5KcY8hJd",
	}

	for _, password := range strong {
		if err := CheckPassword(password, nil); err != nil {
			t.Fatalf("%q was refused: %v", password, err)
		}
	}
}

func TestCheckPasswordLimitsTheLength(t *testing.T) {
	if err := CheckPassword(strings.Repeat("x", maxPasswordBytes+1), nil); err == nil {
		t.Fatal("a password over the limit was accepted")
	}
}

func TestVeryLongStrongPasswordsAreJudgedQuickly(t *testing.T) {
	long := strings.Repeat("k9#Vq2$Lm8@xW4!zR7pT", 40)

	if bits := GuessBits(long, nil); bits < MinGuessBits {
		t.Fatalf("a long strong password scored %.0f bits", bits)
	}
}

func TestUserInputsNeverMakeAPasswordStronger(t *testing.T) {
	password := "johnsmith2024!"

	if with, without := GuessBits(password, []string{"johnsmith"}), GuessBits(password, nil); with > without {
		t.Fatalf("with the name %.1f bits, without %.1f", with, without)
	}
}

func TestMoreCharactersMeanMoreBits(t *testing.T) {
	if short, long := GuessBits("k9#Vq2", nil), GuessBits("k9#Vq2$Lm8@xW4!zR7pT", nil); short >= long {
		t.Fatalf("short %.1f bits, long %.1f bits", short, long)
	}
}

func TestSeparatorsDoNotMakeWordsStronger(t *testing.T) {
	spaced := GuessBits("correct horse battery staple", nil)
	joined := GuessBits("correcthorsebatterystaple", nil)

	if spaced > joined {
		t.Fatalf("with spaces %.1f bits, without %.1f", spaced, joined)
	}
}
