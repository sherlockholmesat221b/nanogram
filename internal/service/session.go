// File: internal/service/session.go

package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/zkcrypto"
)

// Authenticate validates a session, authenticates the request, enforces its
// scope, and advances its replay-protection counter. A valid request on a full
// session also keeps it alive for another idle period (up to its absolute
// limit). Requests that fail any check change nothing.
func (s *Service) Authenticate(
	ctx context.Context,
	r AuthRequest,
	scope string,
) (store.Session, error) {
	var zero store.Session

	idHash := sha256.Sum256(r.SessionID)
	now := s.now()

	session, err := s.store.SessionByIDHash(ctx, idHash, now)
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

	// Full sessions slide with use. The store never lets the expiry pass the
	// session's absolute limit. Recovery sessions are fixed.
	var extendTo time.Time
	if session.Scope == "full" {
		extendTo = now.Add(fullSessionIdle)
	}

	if err := s.store.AdvanceCounter(ctx, idHash, r.Counter, extendTo); err != nil {
		if errors.Is(err, store.ErrConflict) ||
			errors.Is(err, store.ErrNotFound) {
			return zero, ErrUnauthorized
		}
		return zero, ErrInternal
	}

	return session, nil
}
