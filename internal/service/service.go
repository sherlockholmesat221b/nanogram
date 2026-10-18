// File: internal/service/service.go

package service

import (
	"crypto/rand"
	"errors"
	"io"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/auth"
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

	// ErrInternal indicates an internal service failure.
	ErrInternal = errors.New("internal error")
)

// Service implements the application service layer.
type Service struct {
	auth  *auth.Server
	store store.Store
	now   func() time.Time
	rand  io.Reader
}

// New constructs a Service, supplying defaults for Now and Rand when omitted.
func New(cfg Config) *Service {
	now := cfg.Now
	if now == nil {
		now = time.Now
	}

	random := cfg.Rand
	if random == nil {
		random = rand.Reader
	}

	return &Service{
		auth:  cfg.Auth,
		store: cfg.Store,
		now:   now,
		rand:  random,
	}
}
