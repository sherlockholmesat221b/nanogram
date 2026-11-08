// File: internal/service/pow.go

package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/pow"
)

const (
	powBase      = 15
	powServerCap = 20
)

// PowChallenge issues a challenge for the given purpose and username, after
// charging the request to the global and per-username buckets.
func (s *Service) PowChallenge(ctx context.Context, purpose, username string) (pow.Challenge, error) {
	if purpose != "register" && purpose != "login" {
		return pow.Challenge{}, ErrInvalidRequest
	}
	if !usernamePattern.MatchString(username) {
		return pow.Challenge{}, ErrInvalidRequest
	}
	username = canonicalUsername(username)

	now := s.now()
	if !s.anonBucket.Allow(nil, now) {
		return pow.Challenge{}, ErrBusy
	}

	difficulty := s.difficulty(username, purpose, now)
	return pow.Issue(s.secret, purpose, username, difficulty, now.Unix())
}

// hashedUsername is the key for the per-username buckets and the attempts
// counter. The hash prevents the server from holding a plaintext list of
// probed names in memory.
func (s *Service) hashedUsername(username string) []byte {
	h := hmac.New(sha256.New, s.secret)
	h.Write([]byte("zkc/v1/bucket"))
	h.Write([]byte(username))
	return h.Sum(nil)
}

// difficulty returns the current PoW difficulty for the given purpose.
// Register always uses the floor; login scales with the attempt count.
func (s *Service) difficulty(username, purpose string, now time.Time) uint8 {
	if purpose == "register" {
		return powBase
	}
	n := s.attempts.Count(s.hashedUsername(username), now)
	d := powBase + n
	if d > powServerCap {
		d = powServerCap
	}
	return uint8(d)
}

// verifyPow checks the solution, the difficulty floor and the replay cache.
// It returns ErrPowInvalid for any failure.
func (s *Service) verifyPow(purpose, username string, solution *pow.Solution) error {
	if solution == nil {
		return ErrPowInvalid
	}
	now := s.now()
	if err := pow.Verify(s.secret, purpose, username, *solution, now.Unix()); err != nil {
		return ErrPowInvalid
	}
	if solution.Difficulty < s.difficulty(username, purpose, now) {
		return ErrPowInvalid
	}
	if !s.replay.Accept(solution.Nonce, now) {
		return ErrPowInvalid
	}
	return nil
}

// recordAttempt records a login/start for the given username. It is called
// *after* verification passes, so an attacker cannot pollute the counter
// without first paying a valid PoW.
func (s *Service) recordAttempt(username string) {
	s.attempts.Record(s.hashedUsername(username), s.now())
}
