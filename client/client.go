// File: client/client.go

package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/mlkem"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"github.com/bytemare/opaque"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/auth"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/wire"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/zkcrypto"
)

const (
	keySize      = 32
	identitySize = 64 + 32 // ML-KEM-768 seed, then Ed25519 seed
	userIDSize   = 16
)

// Client registers accounts and logs in. All key handling happens here: the
// server only ever sees OPAQUE messages and encrypted blobs.
type Client struct {
	T     Transport
	Heads HeadStore
}

// New returns a Client. When heads is nil the remembered blob versions are
// kept in memory only, which gives no protection across restarts.
func New(t Transport, heads HeadStore) *Client {
	if heads == nil {
		heads = NewMemHeads()
	}

	return &Client{T: t, Heads: heads}
}

// RegisterResult is what a successful registration returns. RecoveryPhrase is
// empty when recovery was not requested. It is shown to the user once and is
// never stored by the client.
type RegisterResult struct {
	UserID         []byte
	RecoveryPhrase string
}

func wipe(b []byte) {
	clear(b)
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}

	return b, nil
}

// sealFirst makes version 1 of a blob and checks it before it is sent: it must
// open again to the same plaintext and carry the hash BlobHash gives.
func sealFirst(key, plaintext, userID []byte, kind zkcrypto.BlobKind) (service.BlobUpload, [32]byte, error) {
	none := service.BlobUpload{}

	blob, hash, err := zkcrypto.SealBlob(key, plaintext, userID, kind, 1, zkcrypto.ZeroHash)
	if err != nil {
		return none, zkcrypto.ZeroHash, err
	}

	opened, err := zkcrypto.OpenBlob(key, blob, userID, kind, 1, zkcrypto.ZeroHash)
	if err != nil || !bytes.Equal(opened, plaintext) {
		wipe(opened)
		return none, zkcrypto.ZeroHash, errors.New("a new blob did not open again")
	}
	wipe(opened)

	check, err := zkcrypto.BlobHash(userID, kind, 1, zkcrypto.ZeroHash, blob)
	if err != nil || check != hash {
		return none, zkcrypto.ZeroHash, errors.New("a new blob has an unexpected hash")
	}

	return service.BlobUpload{
		Kind:     byte(kind),
		Version:  1,
		PrevHash: zkcrypto.ZeroHash,
		Data:     blob,
	}, hash, nil
}

// Register creates an account. The passphrase must be one the client accepts
// (see CheckPassphrase) and must be typed twice. With withRecovery the result
// holds the 24 recovery words, which the caller shows once.
func (c *Client) Register(
	ctx context.Context,
	username, passphrase, confirm string,
	withRecovery bool,
) (RegisterResult, error) {
	var result RegisterResult

	if PasswordInput(passphrase) != PasswordInput(confirm) {
		return result, ErrPassphraseMismatch
	}

	if err := CheckPassphrase(passphrase, false); err != nil {
		return result, fmt.Errorf("%w: %v", ErrWeakPassphrase, err)
	}

	password := []byte(PasswordInput(passphrase))
	defer wipe(password)

	conf := auth.NewConfiguration()

	passwordClient, err := conf.Client()
	if err != nil {
		return result, err
	}
	passwordRequest := passwordClient.RegistrationInit(password).Serialize()

	var (
		recoveryKey    []byte
		recoverySecret []byte
		recoveryClient *opaque.Client
		recoveryReq    []byte
	)
	defer func() {
		wipe(recoveryKey)
		wipe(recoverySecret)
	}()

	if withRecovery {
		recoveryKey, err = zkcrypto.NewRecoveryKey()
		if err != nil {
			return result, err
		}

		recoverySecret, err = zkcrypto.RecoveryLoginSecret(recoveryKey)
		if err != nil {
			return result, err
		}

		recoveryClient, err = conf.Client()
		if err != nil {
			return result, err
		}
		recoveryReq = recoveryClient.RegistrationInit(recoverySecret).Serialize()
	}

	start, err := c.T.RegisterStart(ctx, username, passwordRequest, recoveryReq)
	if err != nil {
		return result, err
	}

	if len(start.UserID) != userIDSize ||
		len(start.PasswordResponse) == 0 ||
		(withRecovery && len(start.RecoveryResponse) == 0) {
		return result, ErrProtocol
	}
	userID := start.UserID

	// The identity inside the OPAQUE record is the user id. Login uses the
	// same one, so the record only opens for this account.
	passwordResponse, err := passwordClient.Deserialize.RegistrationResponse(start.PasswordResponse)
	if err != nil {
		return result, fmt.Errorf("%w: %v", ErrProtocol, err)
	}

	passwordRecord, exportKey := passwordClient.RegistrationFinalize(
		passwordResponse,
		opaque.ClientRegistrationFinalizeOptions{ClientIdentity: userID},
	)
	defer wipe(exportKey)

	wrapKey, err := zkcrypto.DeriveKey(exportKey, zkcrypto.LabelWrap)
	if err != nil {
		return result, err
	}
	defer wipe(wrapKey)

	kek, err := randomBytes(keySize)
	if err != nil {
		return result, err
	}
	defer wipe(kek)

	mek, err := randomBytes(keySize)
	if err != nil {
		return result, err
	}
	defer wipe(mek)

	signSeed, err := randomBytes(ed25519.SeedSize)
	if err != nil {
		return result, err
	}
	defer wipe(signSeed)

	decapsulationKey, err := mlkem.GenerateKey768()
	if err != nil {
		return result, err
	}

	identity := append(decapsulationKey.Bytes(), signSeed...)
	defer wipe(identity)
	if len(identity) != identitySize {
		return result, errors.New("unexpected identity size")
	}

	signKey := ed25519.NewKeyFromSeed(signSeed)
	defer wipe(signKey)

	kekBlob, kekHash, err := sealFirst(wrapKey, kek, userID, zkcrypto.KindKEK)
	if err != nil {
		return result, err
	}

	mekBlob, mekHash, err := sealFirst(kek, mek, userID, zkcrypto.KindMEK)
	if err != nil {
		return result, err
	}

	identityBlob, identityHash, err := sealFirst(kek, identity, userID, zkcrypto.KindIdentity)
	if err != nil {
		return result, err
	}

	finish := service.RegisterFinishRequest{
		UserID:         userID,
		Username:       username,
		PasswordRecord: passwordRecord.Serialize(),
		Blobs:          []service.BlobUpload{kekBlob, mekBlob, identityBlob},
		PublicKeys: []service.PublicKeyUpload{
			{Kind: "mlkem", Key: decapsulationKey.EncapsulationKey().Bytes()},
			{Kind: "sign", Key: []byte(signKey.Public().(ed25519.PublicKey))},
		},
	}

	var phrase string

	if withRecovery {
		recoveryID, err := zkcrypto.RecoveryCredentialID(userID)
		if err != nil {
			return result, err
		}

		recoveryResponse, err := recoveryClient.Deserialize.RegistrationResponse(start.RecoveryResponse)
		if err != nil {
			return result, fmt.Errorf("%w: %v", ErrProtocol, err)
		}

		recoveryRecord, recoveryExport := recoveryClient.RegistrationFinalize(
			recoveryResponse,
			opaque.ClientRegistrationFinalizeOptions{ClientIdentity: recoveryID},
		)
		wipe(recoveryExport)

		recoveryWrap, err := zkcrypto.RecoveryWrapKey(recoveryKey)
		if err != nil {
			return result, err
		}
		defer wipe(recoveryWrap)

		recoveryBlob, _, err := sealFirst(recoveryWrap, kek, userID, zkcrypto.KindRecovery)
		if err != nil {
			return result, err
		}

		phrase, err = zkcrypto.RecoveryPhrase(recoveryKey)
		if err != nil {
			return result, err
		}

		finish.RecoveryRecord = recoveryRecord.Serialize()
		finish.Blobs = append(finish.Blobs, recoveryBlob)
	}

	if err := c.T.RegisterFinish(ctx, finish); err != nil {
		return result, err
	}

	result = RegisterResult{UserID: userID, RecoveryPhrase: phrase}

	for _, h := range []struct {
		kind zkcrypto.BlobKind
		hash [32]byte
	}{
		{zkcrypto.KindKEK, kekHash},
		{zkcrypto.KindMEK, mekHash},
		{zkcrypto.KindIdentity, identityHash},
	} {
		if err := c.Heads.Put(userID, byte(h.kind), Head{Version: 1, Hash: h.hash}); err != nil {
			return result, fmt.Errorf("%w: %v", ErrHeadsNotSaved, err)
		}
	}

	return result, nil
}

// Login logs in with the passphrase, opens the account's blobs and checks
// them against what this device saw before. Every kind of failed login gives
// ErrLoginFailed, and only after the slow key stretching inside the OPAQUE
// library has run.
func (c *Client) Login(ctx context.Context, username, passphrase string) (*Session, error) {
	password := []byte(PasswordInput(passphrase))
	defer wipe(password)

	oc, err := auth.NewConfiguration().Client()
	if err != nil {
		return nil, err
	}

	start, err := c.T.LoginStart(ctx, username, "password", oc.LoginInit(password).Serialize())
	if err != nil {
		return nil, err
	}

	if len(start.UserID) != userIDSize {
		return nil, ErrProtocol
	}

	ke2, err := oc.Deserialize.KE2(start.KE2)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProtocol, err)
	}

	ke3, exportKey, err := oc.LoginFinish(
		ke2,
		opaque.ClientLoginFinishOptions{ClientIdentity: start.UserID},
	)
	if err != nil {
		return nil, ErrLoginFailed
	}
	defer wipe(exportKey)

	info, err := c.T.LoginFinish(ctx, start.LoginID, ke3.Serialize())
	if err != nil {
		if errors.Is(err, service.ErrLoginFailed) {
			return nil, ErrLoginFailed
		}
		return nil, err
	}

	if !bytes.Equal(info.UserID, start.UserID) {
		return nil, ErrProtocol
	}

	requestKey, err := zkcrypto.RequestKey(oc.SessionKey())
	if err != nil {
		return nil, err
	}

	session := &Session{
		UserID:     info.UserID,
		ID:         info.SessionID,
		Scope:      info.Scope,
		requestKey: requestKey,
	}

	blobs, err := c.T.AccountBlobs(ctx, session.Sign("GET", wire.PathAccountBlobs, nil))
	if err != nil {
		session.Wipe()
		return nil, err
	}

	account, warnings, err := c.openAccount(info.UserID, exportKey, blobs)
	if err != nil {
		session.Wipe()
		return nil, err
	}

	session.Account = account
	session.Warnings = warnings

	return session, nil
}

var kindNames = map[zkcrypto.BlobKind]string{
	zkcrypto.KindKEK:      "kek",
	zkcrypto.KindMEK:      "mek",
	zkcrypto.KindIdentity: "identity",
}

// openAccount checks the three account blobs against the remembered heads,
// opens them, and only then remembers the new heads.
func (c *Client) openAccount(userID, exportKey []byte, blobs []service.BlobInfo) (*Account, []string, error) {
	wanted := []zkcrypto.BlobKind{zkcrypto.KindKEK, zkcrypto.KindMEK, zkcrypto.KindIdentity}

	byKind := make(map[zkcrypto.BlobKind]service.BlobInfo, len(blobs))
	for _, b := range blobs {
		kind := zkcrypto.BlobKind(b.Kind)
		if _, known := kindNames[kind]; !known {
			return nil, nil, ErrBadBlobs
		}
		if _, repeated := byKind[kind]; repeated {
			return nil, nil, ErrBadBlobs
		}
		byKind[kind] = b
	}

	var (
		warnings []string
		heads    = make(map[zkcrypto.BlobKind]Head, len(wanted))
	)

	for _, kind := range wanted {
		b, ok := byKind[kind]
		if !ok {
			return nil, nil, ErrBadBlobs
		}

		hash, err := zkcrypto.BlobHash(userID, kind, b.Version, b.PrevHash, b.Data)
		if err != nil {
			return nil, nil, ErrBadBlobs
		}

		known, seen := c.Heads.Get(userID, byte(kind))

		warning, err := checkHead(known, seen, b.Version, b.PrevHash, hash)
		if err != nil {
			return nil, nil, err
		}
		if warning != "" {
			warnings = append(warnings, kindNames[kind]+": "+warning)
		}

		heads[kind] = Head{Version: b.Version, Hash: hash}
	}

	wrapKey, err := zkcrypto.DeriveKey(exportKey, zkcrypto.LabelWrap)
	if err != nil {
		return nil, nil, err
	}
	defer wipe(wrapKey)

	open := func(key []byte, kind zkcrypto.BlobKind) ([]byte, error) {
		b := byKind[kind]

		plaintext, err := zkcrypto.OpenBlob(key, b.Data, userID, kind, b.Version, b.PrevHash)
		if err != nil {
			return nil, ErrBlobRejected
		}

		return plaintext, nil
	}

	kek, err := open(wrapKey, zkcrypto.KindKEK)
	if err != nil {
		return nil, nil, err
	}

	mek, err := open(kek, zkcrypto.KindMEK)
	if err != nil {
		wipe(kek)
		return nil, nil, err
	}

	identity, err := open(kek, zkcrypto.KindIdentity)
	if err != nil {
		wipe(kek)
		wipe(mek)
		return nil, nil, err
	}
	defer wipe(identity)

	if len(kek) != keySize || len(mek) != keySize || len(identity) != identitySize {
		wipe(kek)
		wipe(mek)
		return nil, nil, ErrBlobRejected
	}

	for kind, head := range heads {
		if err := c.Heads.Put(userID, byte(kind), head); err != nil {
			wipe(kek)
			wipe(mek)
			return nil, nil, fmt.Errorf("%w: %v", ErrHeadsNotSaved, err)
		}
	}

	return &Account{
		KEK:       kek,
		MEK:       mek,
		MLKEMSeed: bytes.Clone(identity[:64]),
		SignSeed:  bytes.Clone(identity[64:]),
	}, warnings, nil
}
