// File: internal/service/recovery.go

package service

import (
	"context"
	"errors"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/zkcrypto"
)

// RecoveryView returns the current recovery blob together with the current
// KEK blob's header. It is what a recovery session fetches first, to learn
// the version and hash the next KEK blob chains onto.
func (s *Service) RecoveryView(ctx context.Context, userID []byte) (RecoveryViewResult, error) {
	recovery, err := s.store.CurrentBlob(ctx, userID, store.BlobKindRecovery)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return RecoveryViewResult{}, ErrRecoveryNotSetUp
		}
		return RecoveryViewResult{}, ErrInternal
	}

	kek, err := s.store.CurrentBlob(ctx, userID, store.BlobKindKEK)
	if err != nil {
		return RecoveryViewResult{}, ErrInternal
	}

	kekHash, err := zkcrypto.BlobHash(userID, zkcrypto.KindKEK, kek.Version, kek.PrevHash, kek.Data)
	if err != nil {
		return RecoveryViewResult{}, ErrInternal
	}

	return RecoveryViewResult{
		Recovery: BlobInfo{
			Kind:     recovery.Kind,
			Version:  recovery.Version,
			PrevHash: recovery.PrevHash,
			Data:     recovery.Data,
		},
		KEKHeader: BlobHeader{
			Version:  kek.Version,
			PrevHash: kek.PrevHash,
			Hash:     kekHash,
		},
	}, nil
}

// RecoveryPasswordStart is PasswordChangeStart for a recovery session.
func (s *Service) RecoveryPasswordStart(ctx context.Context, userID, request []byte) ([]byte, error) {
	return s.PasswordChangeStart(ctx, userID, request)
}

// RecoveryPasswordBegin is PasswordChangeBegin for a recovery session.
func (s *Service) RecoveryPasswordBegin(ctx context.Context, userID []byte, expectedVersion uint64, record []byte, kek BlobUpload) error {
	return s.PasswordChangeBegin(ctx, userID, expectedVersion, record, kek)
}

// RecoveryRotateStart returns the OPAQUE registration response for a new
// recovery credential. The credential id is derived from the user id, as at
// registration.
func (s *Service) RecoveryRotateStart(ctx context.Context, userID, request []byte) ([]byte, error) {
	credentialID, err := zkcrypto.RecoveryCredentialID(userID)
	if err != nil {
		return nil, ErrInternal
	}

	response, err := s.auth.RegistrationResponse(request, credentialID)
	if err != nil {
		return nil, ErrInvalidRequest
	}

	return response, nil
}

// RecoveryRotateBegin replaces the current recovery record and blob. It is a
// compare-and-swap on the recovery blob version: the current version must be
// what the client says it saw, and the new blob must be exactly one version
// higher.
func (s *Service) RecoveryRotateBegin(
	ctx context.Context,
	userID []byte,
	expectedVersion uint64,
	record []byte,
	blob BlobUpload,
) error {
	if blob.Kind != store.BlobKindRecovery ||
		expectedVersion == ^uint64(0) ||
		blob.Version != expectedVersion+1 ||
		len(blob.Data) < 41 ||
		len(blob.Data) > 4096 {
		return ErrInvalidRequest
	}

	normalized, err := s.auth.NormalizeRecord(record)
	if err != nil {
		return ErrInvalidRequest
	}

	err = s.store.ReplaceRecovery(
		ctx,
		userID,
		expectedVersion,
		store.OpaqueRecord{
			UserID:     userID,
			Kind:       "recovery",
			Pending:    false,
			Record:     normalized,
			KSFVersion: 1,
		},
		store.Blob{
			UserID:    userID,
			Kind:      store.BlobKindRecovery,
			Version:   blob.Version,
			PrevHash:  blob.PrevHash,
			Data:      blob.Data,
			Pending:   false,
			CreatedAt: s.now(),
		},
	)

	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrConflict):
		return ErrConflict
	case errors.Is(err, store.ErrNotFound):
		return ErrRecoveryNotSetUp
	default:
		return ErrInternal
	}
}

// RecoveryDisable removes the recovery record and blobs. It is idempotent:
// calling it when recovery is already off is not an error.
func (s *Service) RecoveryDisable(ctx context.Context, userID []byte) error {
	err := s.store.DeleteRecovery(ctx, userID)
	if err == nil || errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return ErrInternal
}
