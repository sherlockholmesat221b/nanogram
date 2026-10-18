// File: internal/service/register.go

package service

import (
	"context"
	"errors"
	"io"
	"regexp"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/zkcrypto"
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9_.]{3,32}$`)

const registrationReservationLifetime = 5 * time.Minute

// RegisterStart reserves a username and returns the OPAQUE registration responses.
func (s *Service) RegisterStart(
	ctx context.Context,
	username string,
	passwordReq, recoveryReq []byte,
) (RegisterStartResult, error) {
	var result RegisterStartResult

	if !usernamePattern.MatchString(username) {
		return result, ErrInvalidUsername
	}

	userID := make([]byte, 16)
	if _, err := io.ReadFull(s.rand, userID); err != nil {
		return result, ErrInternal
	}

	now := s.now()
	if err := s.store.ReserveUsername(
		ctx,
		username,
		userID,
		now,
		now.Add(registrationReservationLifetime),
	); err != nil {
		if errors.Is(err, store.ErrTaken) {
			return result, ErrUsernameTaken
		}
		return result, ErrInternal
	}

	passwordResponse, err := s.auth.RegistrationResponse(passwordReq, userID)
	if err != nil {
		return result, ErrInvalidRequest
	}

	result.UserID = userID
	result.PasswordResponse = passwordResponse

	if len(recoveryReq) != 0 {
		credentialID, err := zkcrypto.RecoveryCredentialID(userID)
		if err != nil {
			return RegisterStartResult{}, ErrInternal
		}

		recoveryResponse, err := s.auth.RegistrationResponse(recoveryReq, credentialID)
		if err != nil {
			return RegisterStartResult{}, ErrInvalidRequest
		}

		result.RecoveryResponse = recoveryResponse
	}

	return result, nil
}

// RegisterFinish validates registration data and atomically creates the user.
func (s *Service) RegisterFinish(ctx context.Context, r RegisterFinishRequest) error {
	if !usernamePattern.MatchString(r.Username) {
		return ErrInvalidUsername
	}
	if len(r.UserID) != 16 {
		return ErrInvalidRequest
	}

	passwordRecord, err := s.auth.NormalizeRecord(r.PasswordRecord)
	if err != nil {
		return ErrInvalidRequest
	}

	var records []store.OpaqueRecord
	records = append(records, store.OpaqueRecord{
		UserID:     r.UserID,
		Kind:       "password",
		Record:     passwordRecord,
		KSFVersion: 1,
	})

	hasRecoveryRecord := len(r.RecoveryRecord) != 0
	if hasRecoveryRecord {
		recoveryRecord, err := s.auth.NormalizeRecord(r.RecoveryRecord)
		if err != nil {
			return ErrInvalidRequest
		}

		records = append(records, store.OpaqueRecord{
			UserID:     r.UserID,
			Kind:       "recovery",
			Record:     recoveryRecord,
			KSFVersion: 1,
		})
	}

	blobs, err := validateRegistrationBlobs(r.Blobs, hasRecoveryRecord, r.UserID)
	if err != nil {
		return ErrInvalidRequest
	}

	keys, err := validateRegistrationKeys(r.PublicKeys, r.UserID, s.now())
	if err != nil {
		return ErrInvalidRequest
	}

	now := s.now()
	user := store.User{
		ID:        r.UserID,
		Username:  r.Username,
		CreatedAt: now,
	}

	if err := s.store.CreateUser(ctx, user, records, blobs, keys, now); err != nil {
		switch {
		case errors.Is(err, store.ErrTaken):
			return ErrUsernameTaken
		case errors.Is(err, store.ErrConflict):
			return ErrInvalidRequest
		default:
			return ErrInternal
		}
	}

	return nil
}

func validateRegistrationBlobs(
	uploads []BlobUpload,
	hasRecoveryRecord bool,
	userID []byte,
) ([]store.Blob, error) {
	required := map[byte]bool{
		store.BlobKindKEK:      false,
		store.BlobKindMEK:      false,
		store.BlobKindIdentity: false,
	}

	if hasRecoveryRecord {
		required[store.BlobKindRecovery] = false
	}

	blobs := make([]store.Blob, 0, len(uploads))

	for _, upload := range uploads {
		seen, ok := required[upload.Kind]
		if !ok || seen {
			return nil, ErrInvalidRequest
		}
		if upload.Version != 1 || upload.PrevHash != zkcrypto.ZeroHash {
			return nil, ErrInvalidRequest
		}
		if len(upload.Data) < 41 || len(upload.Data) > 4096 {
			return nil, ErrInvalidRequest
		}

		required[upload.Kind] = true
		blobs = append(blobs, store.Blob{
			UserID:   userID,
			Kind:     upload.Kind,
			Version:  upload.Version,
			PrevHash: upload.PrevHash,
			Data:     upload.Data,
		})
	}

	for _, found := range required {
		if !found {
			return nil, ErrInvalidRequest
		}
	}

	return blobs, nil
}

func validateRegistrationKeys(
	uploads []PublicKeyUpload,
	userID []byte,
	now time.Time,
) ([]store.PublicKey, error) {
	seen := make(map[string]bool, 2)
	keys := make([]store.PublicKey, 0, len(uploads))

	for _, upload := range uploads {
		if upload.Kind != "mlkem" && upload.Kind != "sign" {
			return nil, ErrInvalidRequest
		}
		if seen[upload.Kind] {
			return nil, ErrInvalidRequest
		}
		if len(upload.Key) < 1 || len(upload.Key) > 2048 {
			return nil, ErrInvalidRequest
		}

		seen[upload.Kind] = true
		keys = append(keys, store.PublicKey{
			UserID:    userID,
			Kind:      upload.Kind,
			Version:   1,
			Key:       upload.Key,
			CreatedAt: now,
		})
	}

	return keys, nil
}
