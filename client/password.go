// File: client/password.go

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/bytemare/opaque"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/auth"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/zkcrypto"
)

// ChangePassword changes the password of the logged in account.
//
// Only the key blob that holds the KEK is replaced, locked with a key made
// from the new password. The KEK itself, the MEK and the identity stay as they
// are, so nothing else needs to be re-encrypted. The change is staged on the
// server and takes effect when the client proves the new password with a login,
// which also ends every older session. The returned session replaces s, which
// is wiped.
func (c *Client) ChangePassword(ctx context.Context, s *Session, newPassword, confirm string) (*Session, error) {
	if s == nil || s.Account == nil || s.Scope != "full" {
		return nil, errors.New("a full session with an opened account is needed")
	}

	if PasswordInput(newPassword) != PasswordInput(confirm) {
		return nil, ErrPassphraseMismatch
	}
	if err := CheckPassword(newPassword, []string{s.Username}); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrWeakPassphrase, err)
	}

	password := []byte(PasswordInput(newPassword))
	defer wipe(password)

	oc, err := auth.NewConfiguration().Client()
	if err != nil {
		return nil, err
	}

	response, err := c.T.PasswordStart(ctx, s.Sign, oc.RegistrationInit(password).Serialize())
	if err != nil {
		return nil, err
	}

	registrationResponse, err := oc.Deserialize.RegistrationResponse(response)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProtocol, err)
	}

	record, exportKey := oc.RegistrationFinalize(
		registrationResponse,
		opaque.ClientRegistrationFinalizeOptions{ClientIdentity: s.UserID},
	)
	defer wipe(exportKey)

	wrapKey, err := zkcrypto.DeriveKey(exportKey, zkcrypto.LabelWrap)
	if err != nil {
		return nil, err
	}
	defer wipe(wrapKey)

	next := s.kekVersion + 1

	blob, hash, err := zkcrypto.SealBlob(wrapKey, s.Account.KEK, s.UserID, zkcrypto.KindKEK, next, s.kekHash)
	if err != nil {
		return nil, err
	}

	// The new blob must open with the new key before it is sent.
	opened, err := zkcrypto.OpenBlob(wrapKey, blob, s.UserID, zkcrypto.KindKEK, next, s.kekHash)
	if err != nil || !bytes.Equal(opened, s.Account.KEK) {
		wipe(opened)
		return nil, errors.New("the new key blob did not open again")
	}
	wipe(opened)

	upload := service.BlobUpload{
		Kind:     byte(zkcrypto.KindKEK),
		Version:  next,
		PrevHash: s.kekHash,
		Data:     blob,
	}

	if err := c.T.PasswordBegin(ctx, s.Sign, s.kekVersion, record.Serialize(), upload); err != nil {
		return nil, err
	}

	fresh, err := c.login(ctx, s.Username, newPassword, "pending", &Head{Version: next, Hash: hash})
	if err != nil {
		return nil, err
	}

	s.Wipe()
	return fresh, nil
}
