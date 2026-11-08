// File: internal/service/service.go

package service

import (
	"crypto/rand"
	"errors"
	"io"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/auth"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/limits"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

var (
	// ErrInvalidUsername indicates that a username does not meet the required format.
	ErrInvalidUsername = errors.New("invalid username")

	// ErrUsernameTaken indicates that a username is already reserved or registered.
	ErrUsernameTaken = errors.New("username taken")

	// ErrInvalidRequest indicates that a request is malformed or violates validation rules.
	ErrInvalidRequest = errors.New("invalid request")

	// ErrLoginFailed indicates that authentication failed.
	ErrLoginFailed = errors.New("login failed")

	// ErrUnauthorized indicates that a request is not authorized.
	ErrUnauthorized = errors.New("unauthorized")

	// ErrConflict indicates that a request clashes with the current state, for
	// example a password change that starts from an out of date version.
	ErrConflict = errors.New("conflict")

	// ErrInternal indicates an internal service failure.
	ErrInternal = errors.New("internal error")

	// ErrRecoveryNotSetUp indicates that the account has no recovery set up.
	ErrRecoveryNotSetUp = errors.New("recovery is not set up")

	// ErrPowInvalid indicates that a proof-of-work solution was missing,
	// stale, insufficient, or already used.
	ErrPowInvalid = errors.New("proof of work invalid")

	// ErrBusy indicates that a rate limit or an outstanding-state cap was hit.
	ErrBusy = errors.New("server busy")
)

// Service implements the application service layer.
type Service struct {
	auth  *auth.Server
	store store.Store
	now   func() time.Time
	rand  io.Reader

	secret     []byte
	anonBucket *limits.Buckets
	userBucket *limits.Buckets
	replay     *limits.ReplayCache
	attempts   *limits.Attempts
}

func New(cfg Config) *Service {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	random := cfg.Rand
	if random == nil {
		random = rand.Reader
	}
	secret := cfg.PowSecret
	if len(secret) < 32 {
		secret = make([]byte, 32)
		if _, err := io.ReadFull(random, secret); err != nil {
			panic("service: cannot generate PoW secret: " + err.Error())
		}
	}

	return &Service{
		auth:       cfg.Auth,
		store:      cfg.Store,
		now:        now,
		rand:       random,
		secret:     secret,
		anonBucket: limits.NewBuckets(60, 10, time.Minute),
		userBucket: limits.NewBuckets(20, 5, time.Minute),
		replay:     limits.NewReplayCache(20_000, 60*time.Second),
		attempts:   limits.NewAttempts(32, 15*time.Minute),
	}
}
