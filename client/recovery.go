// File: client/recovery.go

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/bytemare/opaque"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/auth"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/wire"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/zkcrypto"
)

// RecoverWithPhrase sets a new password using the 24-word recovery phrase.
// It returns a new full session. The recovery phrase is unchanged; call
// RotateRecovery next to replace it.
//
// A wrong phrase, an account with no recovery set up, and a phrase that has
// already been rotated all give ErrLoginFailed, after the same slow key
// stretching as a normal login.
func (c *Client) RecoverWithPhrase(
	ctx context.Context,
	username, phrase, newPassword, confirm string,
) (*Session, error) {
	if !ValidUsername(username) {
		return nil, service.ErrInvalidUsername
	}
	if PasswordInput(newPassword) != PasswordInput(confirm) {
		return nil, ErrPassphraseMismatch
	}
	if err := CheckPassword(newPassword, []string{username}); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWeakPassphrase, err)
	}

	recoveryKey, err := zkcrypto.RecoveryKeyFromPhrase(phrase)
	if err != nil {
		return nil, ErrLoginFailed
	}
	defer wipe(recoveryKey)

	loginSecret, err := zkcrypto.RecoveryLoginSecret(recoveryKey)
	if err != nil {
		return nil, err
	}
	defer wipe(loginSecret)

	recoveryWrap, err := zkcrypto.RecoveryWrapKey(recoveryKey)
	if err != nil {
		return nil, err
	}
	defer wipe(recoveryWrap)

	oc, err := auth.NewConfiguration().Client()
	if err != nil {
		return nil, err
	}

	start, err := c.T.LoginStart(ctx, username, "recovery", oc.LoginInit(loginSecret).Serialize())
	if err != nil {
		return nil, err
	}
	if len(start.UserID) != userIDSize {
		return nil, ErrProtocol
	}
	userID := start.UserID

	ke2, err := oc.Deserialize.KE2(start.KE2)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProtocol, err)
	}

	credentialID, err := zkcrypto.RecoveryCredentialID(userID)
	if err != nil {
		return nil, err
	}

	ke3, _, err := oc.LoginFinish(ke2, opaque.ClientLoginFinishOptions{ClientIdentity: credentialID})
	if err != nil {
		return nil, ErrLoginFailed
	}

	info, err := c.T.LoginFinish(ctx, start.LoginID, ke3.Serialize())
	if err != nil {
		if errors.Is(err, service.ErrLoginFailed) {
			return nil, ErrLoginFailed
		}
		return nil, err
	}
	if !bytes.Equal(info.UserID, userID) || info.Scope != "recovery" {
		return nil, ErrProtocol
	}

	requestKey, err := zkcrypto.RequestKey(oc.SessionKey())
	if err != nil {
		return nil, err
	}

	recoverySession := &Session{
		Username:   username,
		UserID:     info.UserID,
		ID:         info.SessionID,
		Scope:      info.Scope,
		requestKey: requestKey,
	}
	// The recovery session's server-side state is destroyed by the pending
	// login; wipe the client half on return either way.
	defer recoverySession.Wipe()

	view, err := c.T.RecoveryBlob(ctx, recoverySession.Sign("GET", wire.PathRecoveryBlob, nil))
	if err != nil {
		return nil, err
	}
	if view.Recovery.Kind != byte(zkcrypto.KindRecovery) {
		return nil, ErrProtocol
	}

	kek, err := zkcrypto.OpenBlob(
		recoveryWrap, view.Recovery.Data, userID,
		zkcrypto.KindRecovery, view.Recovery.Version, view.Recovery.PrevHash,
	)
	if err != nil || len(kek) != keySize {
		wipe(kek)
		return nil, ErrBlobRejected
	}
	defer wipe(kek)

	newPasswordBytes := []byte(PasswordInput(newPassword))
	defer wipe(newPasswordBytes)

	ocNew, err := auth.NewConfiguration().Client()
	if err != nil {
		return nil, err
	}

	passwordResponse, err := c.T.RecoveryPasswordStart(
		ctx, recoverySession.Sign, ocNew.RegistrationInit(newPasswordBytes).Serialize(),
	)
	if err != nil {
		return nil, err
	}

	registrationResponse, err := ocNew.Deserialize.RegistrationResponse(passwordResponse)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProtocol, err)
	}
	record, exportKey := ocNew.RegistrationFinalize(
		registrationResponse,
		opaque.ClientRegistrationFinalizeOptions{ClientIdentity: userID},
	)
	defer wipe(exportKey)

	wrapKey, err := zkcrypto.DeriveKey(exportKey, zkcrypto.LabelWrap)
	if err != nil {
		return nil, err
	}
	defer wipe(wrapKey)

	nextVersion := view.KEKHeader.Version + 1
	kekBlob, kekHash, err := zkcrypto.SealBlob(
		wrapKey, kek, userID, zkcrypto.KindKEK, nextVersion, view.KEKHeader.Hash,
	)
	if err != nil {
		return nil, err
	}

	opened, err := zkcrypto.OpenBlob(wrapKey, kekBlob, userID, zkcrypto.KindKEK, nextVersion, view.KEKHeader.Hash)
	if err != nil || !bytes.Equal(opened, kek) {
		wipe(opened)
		return nil, errors.New("the new key blob did not open again")
	}
	wipe(opened)

	upload := service.BlobUpload{
		Kind:     byte(zkcrypto.KindKEK),
		Version:  nextVersion,
		PrevHash: view.KEKHeader.Hash,
		Data:     kekBlob,
	}

	if err := c.T.RecoveryPasswordBegin(
		ctx, recoverySession.Sign, view.KEKHeader.Version, record.Serialize(), upload,
	); err != nil {
		return nil, err
	}

	return c.login(ctx, username, newPassword, "pending", &Head{Version: nextVersion, Hash: kekHash})
}

// RotateRecovery replaces the 24-word recovery phrase. It requires a full
// session with an opened account, which RecoverWithPhrase returns. The old
// phrase stops working; the returned phrase is the new one and must be shown
// to the user once.
//
// If there is no recovery set up, RotateRecovery returns
// service.ErrRecoveryNotSetUp.
func (c *Client) RotateRecovery(ctx context.Context, s *Session) (string, error) {
	if s == nil || s.Account == nil || s.Scope != "full" {
		return "", errors.New("a full session with an opened account is needed")
	}

	view, err := c.T.RecoveryBlob(ctx, s.Sign("GET", wire.PathAccountRecoveryBlob, nil))
	if err != nil {
		return "", err
	}
	if view.Recovery.Kind != byte(zkcrypto.KindRecovery) {
		return "", ErrProtocol
	}

	recoveryHash, err := zkcrypto.BlobHash(
		s.UserID, zkcrypto.KindRecovery,
		view.Recovery.Version, view.Recovery.PrevHash, view.Recovery.Data,
	)
	if err != nil {
		return "", err
	}
	nextVersion := view.Recovery.Version + 1

	newRecoveryKey, err := zkcrypto.NewRecoveryKey()
	if err != nil {
		return "", err
	}
	defer wipe(newRecoveryKey)

	newLoginSecret, err := zkcrypto.RecoveryLoginSecret(newRecoveryKey)
	if err != nil {
		return "", err
	}
	defer wipe(newLoginSecret)

	newWrapKey, err := zkcrypto.RecoveryWrapKey(newRecoveryKey)
	if err != nil {
		return "", err
	}
	defer wipe(newWrapKey)

	oc, err := auth.NewConfiguration().Client()
	if err != nil {
		return "", err
	}

	recoveryResponse, err := c.T.RecoveryRotateStart(
		ctx, s.Sign, oc.RegistrationInit(newLoginSecret).Serialize(),
	)
	if err != nil {
		return "", err
	}

	registrationResponse, err := oc.Deserialize.RegistrationResponse(recoveryResponse)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrProtocol, err)
	}

	credentialID, err := zkcrypto.RecoveryCredentialID(s.UserID)
	if err != nil {
		return "", err
	}

	record, exportKey := oc.RegistrationFinalize(
		registrationResponse,
		opaque.ClientRegistrationFinalizeOptions{ClientIdentity: credentialID},
	)
	wipe(exportKey)

	newBlob, _, err := zkcrypto.SealBlob(
		newWrapKey, s.Account.KEK, s.UserID, zkcrypto.KindRecovery, nextVersion, recoveryHash,
	)
	if err != nil {
		return "", err
	}

	opened, err := zkcrypto.OpenBlob(newWrapKey, newBlob, s.UserID, zkcrypto.KindRecovery, nextVersion, recoveryHash)
	if err != nil || !bytes.Equal(opened, s.Account.KEK) {
		wipe(opened)
		return "", errors.New("the new recovery blob did not open again")
	}
	wipe(opened)

	upload := service.BlobUpload{
		Kind:     byte(zkcrypto.KindRecovery),
		Version:  nextVersion,
		PrevHash: recoveryHash,
		Data:     newBlob,
	}

	if err := c.T.RecoveryRotateBegin(
		ctx, s.Sign, view.Recovery.Version, record.Serialize(), upload,
	); err != nil {
		return "", err
	}

	return zkcrypto.RecoveryPhrase(newRecoveryKey)
}

// DisableRecovery removes the recovery record and blob. It is idempotent:
// calling it when recovery is already off is not an error. After this, a
// forgotten password means lost data, and the UI should say so.
func (c *Client) DisableRecovery(ctx context.Context, s *Session) error {
	if s == nil || s.Scope != "full" {
		return errors.New("a full session is needed")
	}
	return c.T.RecoveryDisable(ctx, s.Sign)
}
