// File: internal/service/passwordchange.go

package service

import (
	"context"
	"errors"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

// passwordChangeLifetime is how long a begun password change waits for the
// proof of the new password.
const passwordChangeLifetime = 10 * time.Minute

// PasswordChangeStart answers the OPAQUE registration request for a new
// password of an account that is already authenticated. It keeps no state.
func (s *Service) PasswordChangeStart(ctx context.Context, userID, request []byte) ([]byte, error) {
	response, err := s.auth.RegistrationResponse(request, userID)
	if err != nil {
		return nil, ErrInvalidRequest
	}

	return response, nil
}

// PasswordChangeBegin stores the new OPAQUE record and the re-wrapped KEK blob
// as pending. Nothing changes for logins until the new password is proven
// with a login of kind "pending". expectedVersion is the KEK version the
// client started from: a different current version, or a change that is
// already pending, gives ErrConflict.
func (s *Service) PasswordChangeBegin(
	ctx context.Context,
	userID []byte,
	expectedVersion uint64,
	record []byte,
	kek BlobUpload,
) error {
	if kek.Kind != store.BlobKindKEK ||
		expectedVersion == 0 ||
		kek.Version != expectedVersion+1 ||
		len(kek.Data) < 41 ||
		len(kek.Data) > 4096 {
		return ErrInvalidRequest
	}

	normalized, err := s.auth.NormalizeRecord(record)
	if err != nil {
		return ErrInvalidRequest
	}

	now := s.now()

	err = s.store.BeginPasswordChange(
		ctx,
		userID,
		expectedVersion,
		store.OpaqueRecord{
			UserID:     userID,
			Kind:       "password",
			Pending:    true,
			Record:     normalized,
			KSFVersion: 1,
		},
		store.Blob{
			UserID:    userID,
			Kind:      store.BlobKindKEK,
			Version:   kek.Version,
			PrevHash:  kek.PrevHash,
			Data:      kek.Data,
			Pending:   true,
			CreatedAt: now,
		},
		now,
		now.Add(passwordChangeLifetime),
	)

	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrConflict):
		return ErrConflict
	default:
		return ErrInternal
	}
}
