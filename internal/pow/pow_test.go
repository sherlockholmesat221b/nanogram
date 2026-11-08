// File: internal/pow/pow_test.go

package pow

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func testSecret() []byte {
	return bytes.Repeat([]byte{0x42}, 32)
}

func TestMACGolden(t *testing.T) {
	// A fixed nonce and timestamp so the MAC is deterministic.
	nonce := bytes.Repeat([]byte{0x11}, NonceSize)
	mac := computeMAC(testSecret(), "login", "alice", nonce, 15, 1700000000)

	const want = "4634da234987c26ec538852bab16b585735eb9a50e7bfcfa027acfb297c66010"
	if got := hex.EncodeToString(mac); got != want {
		t.Fatalf("MAC = %s, want %s", got, want)
	}
}

func TestSolveVerifyRoundTrip(t *testing.T) {
	c, err := Issue(testSecret(), "login", "alice", 4, 1700000000)
	if err != nil {
		t.Fatal(err)
	}

	counter, err := Solve(c, 1<<20)
	if err != nil {
		t.Fatalf("Solve: %v", err)
	}

	s := Solution{
		Nonce:           c.Nonce,
		Difficulty:      c.Difficulty,
		IssuedAt:        c.IssuedAt,
		MAC:             c.MAC,
		SolutionCounter: counter,
	}

	if err := Verify(testSecret(), "login", "alice", s, 1700000000); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	c, _ := Issue(testSecret(), "login", "alice", 4, 1700000000)
	counter, _ := Solve(c, 1<<20)
	base := Solution{Nonce: c.Nonce, Difficulty: c.Difficulty, IssuedAt: c.IssuedAt, MAC: c.MAC, SolutionCounter: counter}

	now := int64(1700000000)
	cases := map[string]func(*Solution){
		"wrong nonce":      func(s *Solution) { s.Nonce = bytes.Repeat([]byte{0x22}, NonceSize) },
		"wrong difficulty": func(s *Solution) { s.Difficulty++ },
		"wrong issued_at":  func(s *Solution) { s.IssuedAt++ },
		"wrong mac":        func(s *Solution) { s.MAC = bytes.Repeat([]byte{0}, len(s.MAC)) },
		"wrong counter": func(s *Solution) {
			// Pick a counter that definitely does not meet the difficulty.
			// Incrementing by 1 sometimes still satisfies it, because at
			// difficulty d about 1 in 2^d counters is valid.
			for i := uint64(1); i < 1<<20; i++ {
				if !meetsDifficulty(s.Nonce, s.Difficulty, base.SolutionCounter+i) {
					s.SolutionCounter = base.SolutionCounter + i
					return
				}
			}
			panic("no failing counter found")
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := base
			s.Nonce = bytes.Clone(base.Nonce)
			s.MAC = bytes.Clone(base.MAC)
			mutate(&s)
			if err := Verify(testSecret(), "login", "alice", s, now); err == nil {
				t.Fatal("Verify accepted the tampered solution")
			}
		})
	}

	// Wrong purpose: the same solution issued for "login" must not verify
	// against "register".
	if err := Verify(testSecret(), "register", "alice", base, now); err == nil {
		t.Fatal("Verify accepted a solution with a wrong purpose")
	}

	// Wrong secret.
	otherSecret := bytes.Repeat([]byte{0x43}, 32)
	if err := Verify(otherSecret, "login", "alice", base, now); err == nil {
		t.Fatal("Verify accepted a solution signed with another secret")
	}

	// Expired window.
	if err := Verify(testSecret(), "login", "alice", base, now+WindowSeconds+1); err == nil {
		t.Fatal("Verify accepted an expired solution")
	}
}

func TestTrailingZeroBits(t *testing.T) {
	cases := []struct {
		b    []byte
		want int
	}{
		{[]byte{0xff}, 0},
		{[]byte{0xfe}, 1},
		{[]byte{0x80}, 7},
		{[]byte{0x00, 0xff}, 0},  // 0xff at LSB = 0 trailing zeros
		{[]byte{0x00, 0xfe}, 1},  // 0xfe at LSB = 1 trailing zero
		{[]byte{0xff, 0x00}, 8},  // 0x00 at LSB = 8 trailing zeros
		{[]byte{0x00, 0x00}, 16}, // all zeros
	}
	for _, c := range cases {
		if got := trailingZeroBits(c.b); got != c.want {
			t.Fatalf("trailingZeroBits(%x) = %d, want %d", c.b, got, c.want)
		}
	}
}
