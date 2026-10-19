// File: internal/service/login.go

package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/auth"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/zkcrypto"
)

const (
	loginStateLifetime      = 30 * time.Second
	fullSessionLifetime     = 15 * time.Minute
	recoverySessionLifetime = 10 * time.Minute
)

// LoginStart begins an OPAQUE login and stores its short-lived server state.
func (s *Service) LoginStart(
	ctx context.Context,
	username, kind string,
	ke1 []byte,
) (LoginStartResult, error) {
	var result LoginStartResult

	if kind != "password" && kind != "recovery" {
		return result, ErrInvalidRequest
	}

	if !usernamePattern.MatchString(username) {
		return result, ErrInvalidRequest
	}

	user, userErr := s.store.UserByUsername(ctx, username)

	var userID []byte
	var stored *auth.StoredUser

	switch {
	case errors.Is(userErr, store.ErrNotFound):
		// Unknown name: answer with an identity derived from the name, so
		// repeated requests for the same name look the same.
		userID = s.auth.FakeUserID(username)

	case userErr != nil:
		return result, ErrInternal

	default:
		// The real user ID goes back for both kinds, even when the user has
		// no record of the requested kind. Otherwise the answer would show
		// who has switched recovery off.
		userID = user.ID

		record, err := s.store.CurrentOpaqueRecord(ctx, user.ID, kind)
		switch {
		case errors.Is(err, store.ErrNotFound):
			// No record of this kind: stored stays nil and the OPAQUE
			// library answers with a fake record.

		case err != nil:
			return result, ErrInternal

		default:
			credentialID := user.ID

			if kind == "recovery" {
				credentialID, err = zkcrypto.RecoveryCredentialID(user.ID)
				if err != nil {
					return result, ErrInternal
				}
			}

			stored = &auth.StoredUser{
				ID:     credentialID,
				Record: record.Record,
			}
		}
	}

	ke2, state, err := s.auth.LoginStart(ke1, username, stored)
	if err != nil {
		return result, ErrInvalidRequest
	}

	loginID := make([]byte, 32)
	if _, err := io.ReadFull(s.rand, loginID); err != nil {
		return result, ErrInternal
	}

	now := s.now()
	idHash := sha256.Sum256(loginID)

	if err := s.store.PutLoginState(ctx, store.LoginState{
		IDHash:    idHash,
		Username:  username,
		Kind:      kind,
		State:     state,
		ExpiresAt: now.Add(loginStateLifetime),
	}); err != nil {
		return result, ErrInternal
	}

	return LoginStartResult{
		LoginID: loginID,
		UserID:  userID,
		KE2:     ke2,
	}, nil
}

// LoginFinish consumes a login state, verifies the OPAQUE exchange, and creates a session.
func (s *Service) LoginFinish(
	ctx context.Context,
	loginID, ke3 []byte,
) (SessionInfo, error) {
	var result SessionInfo

	now := s.now()
	idHash := sha256.Sum256(loginID)

	loginState, err := s.store.TakeLoginState(ctx, idHash, now)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return result, ErrLoginFailed
		}
		return result, ErrInternal
	}

	if loginState.Kind != "password" && loginState.Kind != "recovery" {
		return result, ErrLoginFailed
	}

	sessionKey, err := s.auth.LoginFinish(loginState.State, ke3)
	if err != nil {
		return result, ErrLoginFailed
	}

	user, err := s.store.UserByUsername(ctx, loginState.Username)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return result, ErrLoginFailed
		}
		return result, ErrInternal
	}

	requestKey, err := zkcrypto.RequestKey(sessionKey)
	if err != nil {
		return result, ErrInternal
	}

	sessionID := make([]byte, 32)
	if _, err := io.ReadFull(s.rand, sessionID); err != nil {
		return result, ErrInternal
	}

	scope := "full"
	lifetime := fullSessionLifetime

	if loginState.Kind == "recovery" {
		scope = "recovery"
		lifetime = recoverySessionLifetime
	}

	if err := s.store.PutSession(ctx, store.Session{
		IDHash:      sha256.Sum256(sessionID),
		UserID:      user.ID,
		Key:         requestKey,
		Scope:       scope,
		LastCounter: 0,
		ExpiresAt:   now.Add(lifetime),
	}); err != nil {
		return result, ErrInternal
	}

	return SessionInfo{
		SessionID: sessionID,
		UserID:    user.ID,
		Scope:     scope,
	}, nil
}

// CurrentBlobs returns the current, non-pending blobs for the requested kinds.
// Missing kinds are skipped.
func (s *Service) CurrentBlobs(
	ctx context.Context,
	userID []byte,
	kinds ...byte,
) ([]BlobInfo, error) {
	result := make([]BlobInfo, 0, len(kinds))

	for _, kind := range kinds {
		blob, err := s.store.CurrentBlob(ctx, userID, kind)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				continue
			}
			return nil, ErrInternal
		}

		result = append(result, BlobInfo{
			Kind:     blob.Kind,
			Version:  blob.Version,
			PrevHash: blob.PrevHash,
			Data:     blob.Data,
		})
	}

	return result, nil
}
