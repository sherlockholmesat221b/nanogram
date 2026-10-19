// File: internal/service/login_test.go

package service

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/bytemare/opaque"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/zkcrypto"
)

// identityRecord finishes an OPAQUE registration with the identities the real
// client must use: the client identity is the credential id (the user id for
// the password, a derived id for the recovery credential) and the server
// identity is nil, so the library falls back to the server public key.
func identityRecord(
	t *testing.T,
	client *opaque.Client,
	responseBytes []byte,
	credentialID []byte,
) []byte {
	t.Helper()

	response, err := client.Deserialize.RegistrationResponse(responseBytes)
	if err != nil {
		t.Fatalf("deserialize registration response: %v", err)
	}

	record, _ := client.RegistrationFinalize(
		response,
		opaque.ClientRegistrationFinalizeOptions{
			ClientIdentity: credentialID,
			ServerIdentity: nil,
		},
	)

	return record.Serialize()
}

// registerUser registers testUsername with the password testPassword and, when
// withRecovery is set, with the recovery secret testRecovery. It returns the
// user id.
func (f *registrationFixture) registerUser(t *testing.T, withRecovery bool) []byte {
	t.Helper()

	ctx := context.Background()

	passwordClient := f.client(t)
	passwordRequest := passwordClient.RegistrationInit([]byte(testPassword)).Serialize()

	var recoveryClient *opaque.Client
	var recoveryRequest []byte

	if withRecovery {
		recoveryClient = f.client(t)
		recoveryRequest = recoveryClient.RegistrationInit([]byte(testRecovery)).Serialize()
	}

	start, err := f.service.RegisterStart(ctx, testUsername, passwordRequest, recoveryRequest)
	if err != nil {
		t.Fatalf("RegisterStart: %v", err)
	}

	finish := RegisterFinishRequest{
		UserID:         start.UserID,
		Username:       testUsername,
		PasswordRecord: identityRecord(t, passwordClient, start.PasswordResponse, start.UserID),
		Blobs:          validBlobs(),
		PublicKeys:     validPublicKeys(),
	}

	if withRecovery {
		recoveryID, err := zkcrypto.RecoveryCredentialID(start.UserID)
		if err != nil {
			t.Fatalf("RecoveryCredentialID: %v", err)
		}

		finish.RecoveryRecord = identityRecord(t, recoveryClient, start.RecoveryResponse, recoveryID)
		finish.Blobs = append(finish.Blobs, BlobUpload{
			Kind:    store.BlobKindRecovery,
			Version: 1,
			Data:    bytes.Repeat([]byte{4}, 41),
		})
	}

	if err := f.service.RegisterFinish(ctx, finish); err != nil {
		t.Fatalf("RegisterFinish: %v", err)
	}

	return start.UserID
}

// loginAttempt holds the client side of one login after LoginStart.
type loginAttempt struct {
	client *opaque.Client
	start  LoginStartResult
	ke3    []byte // nil when the client could not finish
	err    error  // the client's LoginFinish error, if any
}

// attemptLogin runs LoginStart and the client side of the OPAQUE login. It
// does not call the service's LoginFinish.
func (f *registrationFixture) attemptLogin(
	t *testing.T,
	username, kind string,
	secret string,
) loginAttempt {
	t.Helper()

	client := f.client(t)
	ke1 := client.LoginInit([]byte(secret)).Serialize()

	start, err := f.service.LoginStart(context.Background(), username, kind, ke1)
	if err != nil {
		t.Fatalf("LoginStart: %v", err)
	}

	attempt := loginAttempt{client: client, start: start}

	ke2, err := client.Deserialize.KE2(start.KE2)
	if err != nil {
		t.Fatalf("deserialize KE2: %v", err)
	}

	clientID := start.UserID
	if kind == "recovery" {
		clientID, err = zkcrypto.RecoveryCredentialID(start.UserID)
		if err != nil {
			t.Fatalf("RecoveryCredentialID: %v", err)
		}
	}

	ke3, _, err := client.LoginFinish(
		ke2,
		opaque.ClientLoginFinishOptions{
			ClientIdentity: clientID,
			ServerIdentity: nil,
		},
	)
	if err != nil {
		attempt.err = err
		return attempt
	}

	attempt.ke3 = ke3.Serialize()
	return attempt
}

// session logs in completely and returns the session and the request key the
// client derives from its OPAQUE session key.
func (f *registrationFixture) session(
	t *testing.T,
	kind, secret string,
) (SessionInfo, []byte) {
	t.Helper()

	attempt := f.attemptLogin(t, testUsername, kind, secret)
	if attempt.err != nil {
		t.Fatalf("client could not finish login: %v", attempt.err)
	}

	info, err := f.service.LoginFinish(context.Background(), attempt.start.LoginID, attempt.ke3)
	if err != nil {
		t.Fatalf("LoginFinish: %v", err)
	}

	key, err := zkcrypto.RequestKey(attempt.client.SessionKey())
	if err != nil {
		t.Fatalf("RequestKey: %v", err)
	}

	return info, key
}

func signed(
	key, sessionID []byte,
	counter uint64,
	method, path string,
	body []byte,
) AuthRequest {
	return AuthRequest{
		SessionID: sessionID,
		Counter:   counter,
		Method:    method,
		Path:      path,
		Body:      body,
		MAC:       zkcrypto.RequestMAC(key, method, path, counter, body),
	}
}

func TestLoginAndAuthenticate(t *testing.T) {
	f := newRegistrationFixture(t)
	userID := f.registerUser(t, false)

	info, key := f.session(t, "password", testPassword)

	if info.Scope != "full" {
		t.Fatalf("scope = %q, want full", info.Scope)
	}
	if len(info.SessionID) != 32 {
		t.Fatalf("session id length = %d, want 32", len(info.SessionID))
	}
	if !bytes.Equal(info.UserID, userID) {
		t.Fatal("session belongs to a different user id")
	}

	for counter := uint64(1); counter <= 2; counter++ {
		session, err := f.service.Authenticate(
			context.Background(),
			signed(key, info.SessionID, counter, "GET", "/v1/account/blobs", nil),
			"full",
		)
		if err != nil {
			t.Fatalf("Authenticate counter %d: %v", counter, err)
		}
		if !bytes.Equal(session.UserID, userID) {
			t.Fatal("Authenticate returned a different user")
		}
	}
}

func TestSessionStoresOnlyTheDerivedKey(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, false)

	attempt := f.attemptLogin(t, testUsername, "password", testPassword)
	if attempt.err != nil {
		t.Fatalf("client could not finish login: %v", attempt.err)
	}

	info, err := f.service.LoginFinish(context.Background(), attempt.start.LoginID, attempt.ke3)
	if err != nil {
		t.Fatalf("LoginFinish: %v", err)
	}

	stored, err := f.store.SessionByIDHash(
		context.Background(),
		sha256.Sum256(info.SessionID),
		f.now,
	)
	if err != nil {
		t.Fatalf("stored session: %v", err)
	}

	wantKey, err := zkcrypto.RequestKey(attempt.client.SessionKey())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(stored.Key, wantKey) {
		t.Fatal("stored key is not the derived request key")
	}
	if bytes.Equal(stored.Key, attempt.client.SessionKey()) {
		t.Fatal("the raw OPAQUE session key was stored")
	}
}

func TestLoginFinishRejectsForgedKE3(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, false)

	attempt := f.attemptLogin(t, testUsername, "password", testPassword)
	if attempt.err != nil {
		t.Fatalf("client could not finish login: %v", attempt.err)
	}

	forged := bytes.Clone(attempt.ke3)
	forged[len(forged)-1] ^= 1

	_, err := f.service.LoginFinish(context.Background(), attempt.start.LoginID, forged)
	if !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("forged KE3: error = %v, want ErrLoginFailed", err)
	}
}

func TestLoginIDWorksOnlyOnce(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, false)

	attempt := f.attemptLogin(t, testUsername, "password", testPassword)
	if attempt.err != nil {
		t.Fatalf("client could not finish login: %v", attempt.err)
	}

	if _, err := f.service.LoginFinish(context.Background(), attempt.start.LoginID, attempt.ke3); err != nil {
		t.Fatalf("first LoginFinish: %v", err)
	}

	_, err := f.service.LoginFinish(context.Background(), attempt.start.LoginID, attempt.ke3)
	if !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("second LoginFinish: error = %v, want ErrLoginFailed", err)
	}
}

func TestFailedFinishUsesUpTheLoginID(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, false)

	attempt := f.attemptLogin(t, testUsername, "password", testPassword)
	if attempt.err != nil {
		t.Fatalf("client could not finish login: %v", attempt.err)
	}

	forged := bytes.Clone(attempt.ke3)
	forged[0] ^= 1

	if _, err := f.service.LoginFinish(context.Background(), attempt.start.LoginID, forged); !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("forged KE3: error = %v, want ErrLoginFailed", err)
	}

	// The right KE3 must not work after a failed try with the same login id.
	_, err := f.service.LoginFinish(context.Background(), attempt.start.LoginID, attempt.ke3)
	if !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("retry after failure: error = %v, want ErrLoginFailed", err)
	}
}

func TestLoginStateExpires(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, false)

	attempt := f.attemptLogin(t, testUsername, "password", testPassword)
	if attempt.err != nil {
		t.Fatalf("client could not finish login: %v", attempt.err)
	}

	f.now = f.now.Add(loginStateLifetime + time.Second)

	_, err := f.service.LoginFinish(context.Background(), attempt.start.LoginID, attempt.ke3)
	if !errors.Is(err, ErrLoginFailed) {
		t.Fatalf("expired login state: error = %v, want ErrLoginFailed", err)
	}
}

func TestWrongPassphraseFailsOnTheClient(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, true)

	attempt := f.attemptLogin(t, testUsername, "password", "not the passphrase")
	if attempt.err == nil {
		t.Fatal("client finished a login with the wrong passphrase")
	}
}

func TestPasswordAndRecoverySecretsAreNotInterchangeable(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, true)

	if attempt := f.attemptLogin(t, testUsername, "recovery", testPassword); attempt.err == nil {
		t.Fatal("the password worked as a recovery secret")
	}

	if attempt := f.attemptLogin(t, testUsername, "password", testRecovery); attempt.err == nil {
		t.Fatal("the recovery secret worked as a password")
	}
}

func TestUnknownUserLooksLikeARealUser(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, false)

	known := f.attemptLogin(t, testUsername, "password", testPassword)
	unknown := f.attemptLogin(t, "mallory", "password", testPassword)

	if len(unknown.start.UserID) != 16 || len(unknown.start.LoginID) != 32 {
		t.Fatalf(
			"unknown user: user id %d bytes, login id %d bytes",
			len(unknown.start.UserID), len(unknown.start.LoginID),
		)
	}
	if len(unknown.start.KE2) != len(known.start.KE2) {
		t.Fatalf(
			"KE2 lengths differ: real=%d unknown=%d",
			len(known.start.KE2), len(unknown.start.KE2),
		)
	}
	if unknown.err == nil {
		t.Fatal("the client finished a login against an unknown user")
	}

	again := f.attemptLogin(t, "mallory", "password", testPassword)
	if !bytes.Equal(again.start.UserID, unknown.start.UserID) {
		t.Fatal("an unknown user got a different user id on the second request")
	}
}

func TestMissingRecoveryRecordLooksLikeAnyOtherUser(t *testing.T) {
	f := newRegistrationFixture(t)
	userID := f.registerUser(t, false)

	password := f.attemptLogin(t, testUsername, "password", testPassword)
	recovery := f.attemptLogin(t, testUsername, "recovery", testRecovery)

	if !bytes.Equal(recovery.start.UserID, userID) ||
		!bytes.Equal(password.start.UserID, userID) {
		t.Fatal("the user id differs between the two kinds")
	}
	if len(recovery.start.KE2) != len(password.start.KE2) {
		t.Fatalf(
			"KE2 lengths differ: password=%d recovery=%d",
			len(password.start.KE2), len(recovery.start.KE2),
		)
	}
	if recovery.err == nil {
		t.Fatal("the client finished a recovery login for a user without recovery")
	}
}

func TestLoginStartRejectsBadInput(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, false)

	ke1 := f.client(t).LoginInit([]byte(testPassword)).Serialize()

	tests := []struct {
		name     string
		username string
		kind     string
		ke1      []byte
	}{
		{"unknown kind", testUsername, "admin", ke1},
		{"empty kind", testUsername, "", ke1},
		{"capital letters", "Alice", "password", ke1},
		{"too long", string(bytes.Repeat([]byte{'a'}, 33)), "password", ke1},
		{"too short", "al", "password", ke1},
		{"garbage KE1, known user", testUsername, "password", []byte{1, 2, 3}},
		{"garbage KE1, unknown user", "mallory", "password", []byte{1, 2, 3}},
		{"empty KE1", testUsername, "password", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := f.service.LoginStart(context.Background(), tt.username, tt.kind, tt.ke1)
			if !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestRecoverySessionHasRecoveryScope(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, true)

	info, key := f.session(t, "recovery", testRecovery)
	if info.Scope != "recovery" {
		t.Fatalf("scope = %q, want recovery", info.Scope)
	}

	request := signed(key, info.SessionID, 1, "GET", "/v1/recovery/blob", nil)

	if _, err := f.service.Authenticate(context.Background(), request, "full"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("recovery session with scope full: error = %v, want ErrUnauthorized", err)
	}

	// A scope mismatch must not use up the counter.
	if _, err := f.service.Authenticate(context.Background(), request, "recovery"); err != nil {
		t.Fatalf("recovery session with scope recovery: %v", err)
	}
}

func TestFullSessionIsRejectedForRecoveryScope(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, true)

	info, key := f.session(t, "password", testPassword)

	request := signed(key, info.SessionID, 1, "GET", "/v1/recovery/blob", nil)

	if _, err := f.service.Authenticate(context.Background(), request, "recovery"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("full session with scope recovery: error = %v, want ErrUnauthorized", err)
	}
}

func TestAuthenticateRejectsUnknownScope(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, false)

	info, key := f.session(t, "password", testPassword)

	for _, scope := range []string{"", "admin", "FULL"} {
		request := signed(key, info.SessionID, 1, "GET", "/v1/account/blobs", nil)

		if _, err := f.service.Authenticate(context.Background(), request, scope); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("scope %q: error = %v, want ErrUnauthorized", scope, err)
		}
	}
}

func TestBadMACDoesNotUseUpTheCounter(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, false)

	info, key := f.session(t, "password", testPassword)

	bad := signed(key, info.SessionID, 1, "GET", "/v1/account/blobs", nil)
	bad.MAC[0] ^= 1

	if _, err := f.service.Authenticate(context.Background(), bad, "full"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("bad MAC: error = %v, want ErrUnauthorized", err)
	}

	good := signed(key, info.SessionID, 1, "GET", "/v1/account/blobs", nil)
	if _, err := f.service.Authenticate(context.Background(), good, "full"); err != nil {
		t.Fatalf("right MAC with the same counter after a bad one: %v", err)
	}
}

func TestCounterMustIncrease(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, false)

	info, key := f.session(t, "password", testPassword)

	steps := []struct {
		counter uint64
		wantOK  bool
	}{
		{5, true},
		{5, false}, // replay
		{4, false}, // lower
		{0, false},
		{6, true},
	}

	for _, step := range steps {
		request := signed(key, info.SessionID, step.counter, "GET", "/v1/account/blobs", nil)
		_, err := f.service.Authenticate(context.Background(), request, "full")

		if step.wantOK && err != nil {
			t.Fatalf("counter %d: %v", step.counter, err)
		}
		if !step.wantOK && !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("counter %d: error = %v, want ErrUnauthorized", step.counter, err)
		}
	}
}

func TestMACCoversEveryPartOfTheRequest(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, false)

	info, key := f.session(t, "password", testPassword)

	// All of these carry a MAC made for a different request.
	mac := zkcrypto.RequestMAC(key, "POST", "/v1/x", 7, []byte("body"))

	tests := []struct {
		name    string
		method  string
		path    string
		counter uint64
		body    []byte
	}{
		{"method", "GET", "/v1/x", 7, []byte("body")},
		{"path", "POST", "/v1/y", 7, []byte("body")},
		{"counter", "POST", "/v1/x", 8, []byte("body")},
		{"body", "POST", "/v1/x", 7, []byte("other")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := AuthRequest{
				SessionID: info.SessionID,
				Counter:   tt.counter,
				Method:    tt.method,
				Path:      tt.path,
				Body:      tt.body,
				MAC:       mac,
			}

			if _, err := f.service.Authenticate(context.Background(), request, "full"); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("error = %v, want ErrUnauthorized", err)
			}
		})
	}

	// And the request the MAC was made for does work.
	request := AuthRequest{
		SessionID: info.SessionID,
		Counter:   7,
		Method:    "POST",
		Path:      "/v1/x",
		Body:      []byte("body"),
		MAC:       mac,
	}
	if _, err := f.service.Authenticate(context.Background(), request, "full"); err != nil {
		t.Fatalf("the matching request: %v", err)
	}
}

func TestSessionExpires(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, true)

	full, fullKey := f.session(t, "password", testPassword)
	recovery, recoveryKey := f.session(t, "recovery", testRecovery)

	f.now = f.now.Add(recoverySessionLifetime + time.Second)

	request := signed(recoveryKey, recovery.SessionID, 1, "GET", "/v1/recovery/blob", nil)
	if _, err := f.service.Authenticate(context.Background(), request, "recovery"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired recovery session: error = %v, want ErrUnauthorized", err)
	}

	// The full session lives longer and is still good here.
	request = signed(fullKey, full.SessionID, 1, "GET", "/v1/account/blobs", nil)
	if _, err := f.service.Authenticate(context.Background(), request, "full"); err != nil {
		t.Fatalf("full session after the recovery lifetime: %v", err)
	}

	f.now = f.now.Add(fullSessionIdle + time.Second)

	request = signed(fullKey, full.SessionID, 2, "GET", "/v1/account/blobs", nil)
	if _, err := f.service.Authenticate(context.Background(), request, "full"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expired full session: error = %v, want ErrUnauthorized", err)
	}
}

func TestAuthenticateRejectsUnknownSession(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, false)

	_, key := f.session(t, "password", testPassword)

	request := signed(key, bytes.Repeat([]byte{9}, 32), 1, "GET", "/v1/account/blobs", nil)
	if _, err := f.service.Authenticate(context.Background(), request, "full"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unknown session: error = %v, want ErrUnauthorized", err)
	}
}

func TestCurrentBlobsSkipsMissingKinds(t *testing.T) {
	f := newRegistrationFixture(t)
	userID := f.registerUser(t, false)

	blobs, err := f.service.CurrentBlobs(
		context.Background(),
		userID,
		store.BlobKindKEK,
		store.BlobKindRecovery,
		store.BlobKindMEK,
	)
	if err != nil {
		t.Fatalf("CurrentBlobs: %v", err)
	}

	if len(blobs) != 2 ||
		blobs[0].Kind != store.BlobKindKEK ||
		blobs[1].Kind != store.BlobKindMEK {
		t.Fatalf("unexpected blobs: %+v", blobs)
	}
}

func TestSessionSlidesWithActivity(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, false)

	info, key := f.session(t, "password", testPassword)

	// One hour in total, which is longer than one idle period, but never
	// more than 20 minutes between two requests.
	for counter := uint64(1); counter <= 3; counter++ {
		f.now = f.now.Add(20 * time.Minute)

		request := signed(key, info.SessionID, counter, "GET", "/v1/account/blobs", nil)
		if _, err := f.service.Authenticate(context.Background(), request, "full"); err != nil {
			t.Fatalf("request %d: %v", counter, err)
		}
	}
}

func TestSessionNeverOutlivesItsMaximum(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, false)

	info, key := f.session(t, "password", testPassword)
	start := f.now

	for counter := uint64(1); ; counter++ {
		f.now = f.now.Add(20 * time.Minute)

		request := signed(key, info.SessionID, counter, "GET", "/v1/account/blobs", nil)
		_, err := f.service.Authenticate(context.Background(), request, "full")

		if f.now.Before(start.Add(fullSessionMax)) {
			if err != nil {
				t.Fatalf("%v after login: %v", f.now.Sub(start), err)
			}
			continue
		}

		if !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("%v after login: error = %v, want ErrUnauthorized", f.now.Sub(start), err)
		}
		return
	}
}

func TestRecoverySessionDoesNotSlide(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, true)

	info, key := f.session(t, "recovery", testRecovery)

	f.now = f.now.Add(6 * time.Minute)

	request := signed(key, info.SessionID, 1, "GET", "/v1/recovery/blob", nil)
	if _, err := f.service.Authenticate(context.Background(), request, "recovery"); err != nil {
		t.Fatalf("first request: %v", err)
	}

	// 11 minutes after the login: past the fixed 10 minutes.
	f.now = f.now.Add(5 * time.Minute)

	request = signed(key, info.SessionID, 2, "GET", "/v1/recovery/blob", nil)
	if _, err := f.service.Authenticate(context.Background(), request, "recovery"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("second request: error = %v, want ErrUnauthorized", err)
	}
}

func TestInvalidRequestDoesNotExtendTheSession(t *testing.T) {
	f := newRegistrationFixture(t)
	f.registerUser(t, false)

	info, key := f.session(t, "password", testPassword)

	f.now = f.now.Add(20 * time.Minute)

	bad := signed(key, info.SessionID, 1, "GET", "/v1/account/blobs", nil)
	bad.MAC[0] ^= 1

	if _, err := f.service.Authenticate(context.Background(), bad, "full"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("bad MAC: error = %v, want ErrUnauthorized", err)
	}

	// 31 minutes after the login. Without the bad request nothing was
	// extended, so the session has run out.
	f.now = f.now.Add(11 * time.Minute)

	good := signed(key, info.SessionID, 1, "GET", "/v1/account/blobs", nil)
	if _, err := f.service.Authenticate(context.Background(), good, "full"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("after the idle period: error = %v, want ErrUnauthorized", err)
	}
}
