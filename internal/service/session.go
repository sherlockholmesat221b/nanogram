// File: internal/service/session.go

package service

import (
	"context"
	"crypto/sha256"
	"errors"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/zkcrypto"
)

// Authenticate validates a session, authenticates the request, enforces its
// scope, and advances its replay-protection counter.
func (s *Service) Authenticate(
	ctx context.Context,
	r AuthRequest,
	scope string,
) (store.Session, error) {
	var zero store.Session

	idHash := sha256.Sum256(r.SessionID)

	session, err := s.store.SessionByIDHash(ctx, idHash, s.now())
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return zero, ErrUnauthorized
		}
		return zero, ErrInternal
	}

	if !zkcrypto.VerifyRequestMAC(
		session.Key,
		r.Method,
		r.Path,
		r.Counter,
		r.Body,
		r.MAC,
	) {
		return zero, ErrUnauthorized
	}

	switch scope {
	case "full":
		if session.Scope != "full" {
			return zero, ErrUnauthorized
		}
	case "recovery":
		if session.Scope != "recovery" {
			return zero, ErrUnauthorized
		}
	default:
		return zero, ErrUnauthorized
	}

	if err := s.store.AdvanceCounter(ctx, idHash, r.Counter); err != nil {
		if errors.Is(err, store.ErrConflict) ||
			errors.Is(err, store.ErrNotFound) {
			return zero, ErrUnauthorized
		}
		return zero, ErrInternal
	}

	return session, nil
}
