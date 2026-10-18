// File: internal/zkcrypto/mlkem_test.go

package zkcrypto

import (
	"bytes"
	"crypto/mlkem"
	"testing"
)

func TestMLKEM768(t *testing.T) {
	// Test 1: Generate key, check seed length, restore and check EncapsulationKey bytes equality
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		t.Fatalf("GenerateKey768 failed: %v", err)
	}

	seed := dk.Bytes()
	if len(seed) != 64 {
		t.Errorf("expected seed length 64, got %d", len(seed))
	}

	dkRestored, err := mlkem.NewDecapsulationKey768(seed)
	if err != nil {
		t.Fatalf("NewDecapsulationKey768 failed: %v", err)
	}

	origEkBytes := dk.EncapsulationKey().Bytes()
	restoredEkBytes := dkRestored.EncapsulationKey().Bytes()

	if len(origEkBytes) != 1184 {
		t.Errorf("expected encapsulation key length 1184, got %d", len(origEkBytes))
	}

	if !bytes.Equal(origEkBytes, restoredEkBytes) {
		t.Fatalf("restored encapsulation key does not match original")
	}

	// Test 2: Encapsulate with restored encapsulation key, decapsulate with restored decapsulation key, check shared keys equal
	ek, err := mlkem.NewEncapsulationKey768(origEkBytes)
	if err != nil {
		t.Fatalf("NewEncapsulationKey768 failed: %v", err)
	}

	sharedKey1, ciphertext := ek.Encapsulate()
	if len(ciphertext) != 1088 {
		t.Errorf("expected ciphertext length 1088, got %d", len(ciphertext))
	}
	if len(sharedKey1) != 32 {
		t.Errorf("expected shared key length 32, got %d", len(sharedKey1))
	}

	sharedKey2, err := dkRestored.Decapsulate(ciphertext)
	if err != nil {
		t.Fatalf("Decapsulate failed: %v", err)
	}

	if !bytes.Equal(sharedKey1, sharedKey2) {
		t.Fatalf("shared keys are not equal")
	}

	// Test 3: Flipping one byte of the ciphertext still decapsulates without error but gives a different shared key (implicit rejection)
	badCiphertext := make([]byte, len(ciphertext))
	copy(badCiphertext, ciphertext)
	badCiphertext[0] ^= 0x01

	sharedKey3, err := dkRestored.Decapsulate(badCiphertext)
	if err != nil {
		t.Fatalf("Decapsulate on bad ciphertext failed with error (expected implicit rejection without error): %v", err)
	}

	if bytes.Equal(sharedKey1, sharedKey3) {
		t.Fatalf("expected implicit rejection to produce a different shared key, but got identical shared key")
	}
}
