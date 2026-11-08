// File: internal/pow/pow.go

// Package pow implements the stateless proof of work for the unauthenticated
// endpoints. The server issues a challenge signed with an HMAC; the client
// searches a counter until the hash of the challenge meets the difficulty;
// the server verifies the HMAC, the difficulty floor, the hash and the
// window. Nothing is stored server-side except a bounded replay cache.
package pow

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/blake2b"
)

const (
	// LabelChallenge and LabelSolve are the domain-separation labels. They
	// are part of the wire format and must never change once clients exist.
	LabelChallenge = "zkc/v1/pow"
	LabelSolve     = "zkc/v1/pow-solve"

	// WindowSeconds is how long a challenge is valid. A solution older than
	// this is refused.
	WindowSeconds = 60

	// NonceSize is the length of the random nonce in a challenge.
	NonceSize = 16
)

// ErrInvalid is returned for every failure to verify a solution. The caller
// must not distinguish the cases.
var ErrInvalid = errors.New("pow: invalid")

// Challenge is what the server issues. Its fields are all bound by MAC.
type Challenge struct {
	Nonce      []byte
	Difficulty uint8
	IssuedAt   int64 // Unix seconds
	MAC        []byte
}

// Solution is what the client sends back. It carries the challenge fields
// plus the counter that satisfies the difficulty.
type Solution struct {
	Nonce           []byte
	Difficulty      uint8
	IssuedAt        int64
	MAC             []byte
	SolutionCounter uint64
}

// Issue creates a challenge for the given purpose and username, at the given
// difficulty, timestamped at now (Unix seconds). The nonce is drawn from
// crypto/rand.
func Issue(secret []byte, purpose, username string, difficulty uint8, now int64) (Challenge, error) {
	if len(secret) < 32 {
		return Challenge{}, errors.New("pow: secret too short")
	}

	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return Challenge{}, err
	}

	return Challenge{
		Nonce:      nonce,
		Difficulty: difficulty,
		IssuedAt:   now,
		MAC:        computeMAC(secret, purpose, username, nonce, difficulty, now),
	}, nil
}

// Verify checks a solution against the MAC, the time window and the hash.
// The caller checks the difficulty floor separately (see requiredDifficulty)
// because that depends on the current state.
func Verify(secret []byte, purpose, username string, s Solution, now int64) error {
	if len(secret) < 32 {
		return ErrInvalid
	}
	if len(s.Nonce) != NonceSize || len(s.MAC) != sha256.Size {
		return ErrInvalid
	}
	if s.IssuedAt > now || now-s.IssuedAt > WindowSeconds {
		return ErrInvalid
	}

	expected := computeMAC(secret, purpose, username, s.Nonce, s.Difficulty, s.IssuedAt)
	if !hmac.Equal(expected, s.MAC) {
		return ErrInvalid
	}

	if !meetsDifficulty(s.Nonce, s.Difficulty, s.SolutionCounter) {
		return ErrInvalid
	}

	return nil
}

// Solve searches for a counter that satisfies the challenge. maxCounter
// bounds the search; if no solution is found within that many tries, the
// challenge is treated as invalid. The caller chooses maxCounter from its
// own cap, not from the challenge, so a hostile server cannot make the
// client search forever.
func Solve(c Challenge, maxCounter uint64) (uint64, error) {
	for i := uint64(0); i < maxCounter; i++ {
		if meetsDifficulty(c.Nonce, c.Difficulty, i) {
			return i, nil
		}
	}
	return 0, errors.New("pow: no solution within the search bound")
}

// computeMAC binds nonce, difficulty, issued_at, purpose and username.
// The order and the separator byte matter: they are the wire format.
func computeMAC(secret []byte, purpose, username string, nonce []byte, difficulty uint8, issuedAt int64) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(LabelChallenge))

	var b [1]byte
	b[0] = difficulty
	h.Write(b[:])

	var t [8]byte
	binary.BigEndian.PutUint64(t[:], uint64(issuedAt))
	h.Write(t[:])

	h.Write([]byte(purpose))
	h.Write([]byte{0})
	h.Write([]byte(username))
	h.Write(nonce)

	return h.Sum(nil)
}

func meetsDifficulty(nonce []byte, difficulty uint8, counter uint64) bool {
	h, err := blake2b.New256(nil)
	if err != nil {
		return false
	}
	h.Write([]byte(LabelSolve))
	h.Write(nonce)

	var c [8]byte
	binary.BigEndian.PutUint64(c[:], counter)
	h.Write(c[:])

	return trailingZeroBits(h.Sum(nil)) >= int(difficulty)
}

func trailingZeroBits(b []byte) int {
	n := 0
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] == 0 {
			n += 8
			continue
		}
		for j := 0; j < 8; j++ {
			if b[i]&(1<<uint(j)) == 0 {
				n++
			} else {
				return n
			}
		}
	}
	return n
}
