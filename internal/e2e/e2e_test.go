// File: internal/e2e/e2e_test.go

// Package e2e runs the whole stack in one process: the client library, the
// HTTP transport, the HTTP handlers, the service and the in-memory store.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bytemare/opaque"

	"gitlab.com/sherlockholmesat221b/nanogram/client"
	"gitlab.com/sherlockholmesat221b/nanogram/client/httptransport"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/api"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/auth"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/pow"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/store/memstore"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/wire"
)

type stack struct {
	server    *httptest.Server
	transport *httptransport.Transport
	client    *client.Client
}

func newStack(t *testing.T) *stack {
	t.Helper()

	keys := auth.GenerateServerKeys(auth.NewConfiguration())

	svc := service.New(service.Config{
		Auth:  auth.NewServer(keys),
		Store: memstore.New(),
	})

	server := httptest.NewServer(api.New(svc, nil))
	t.Cleanup(server.Close)

	transport := httptransport.New(server.URL, server.Client())

	return &stack{
		server:    server,
		transport: transport,
		client:    client.New(transport, nil, nil),
	}
}

func passphrase(t *testing.T) string {
	t.Helper()

	p, err := client.GeneratePassphrase(client.DefaultPassphraseWords)
	if err != nil {
		t.Fatal(err)
	}

	return p
}

func TestRegisterAndLoginOverHTTP(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	pass := passphrase(t)

	result, err := s.client.Register(ctx, "alice", pass, pass, true)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if len(strings.Fields(result.RecoveryPhrase)) != 24 {
		t.Fatalf("recovery phrase: %q", result.RecoveryPhrase)
	}

	first, err := s.client.Login(ctx, "alice", pass)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	second, err := s.client.Login(ctx, "alice", pass)
	if err != nil {
		t.Fatalf("second Login: %v", err)
	}

	if !bytes.Equal(first.Account.KEK, second.Account.KEK) ||
		!bytes.Equal(first.Account.MEK, second.Account.MEK) {
		t.Fatal("two logins opened different keys")
	}
	if !bytes.Equal(first.UserID, result.UserID) {
		t.Fatal("the session belongs to another user")
	}
}

func TestFailuresLookTheSameOverHTTP(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	pass := passphrase(t)

	if _, err := s.client.Register(ctx, "alice", pass, pass, false); err != nil {
		t.Fatal(err)
	}

	_, wrong := s.client.Login(ctx, "alice", passphrase(t))
	_, unknown := s.client.Login(ctx, "mallory", pass)

	if !errors.Is(wrong, client.ErrLoginFailed) || !errors.Is(unknown, client.ErrLoginFailed) {
		t.Fatalf("errors: %v and %v", wrong, unknown)
	}
	if wrong.Error() != unknown.Error() {
		t.Fatalf("different messages: %q and %q", wrong, unknown)
	}
}

func TestUsernameRulesOverHTTP(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	pass := passphrase(t)

	if _, err := s.client.Register(ctx, "alice", pass, pass, false); err != nil {
		t.Fatal(err)
	}

	if _, err := s.client.Register(ctx, "alice", pass, pass, false); !errors.Is(err, service.ErrUsernameTaken) {
		t.Fatalf("taken name: error = %v", err)
	}

	if _, err := s.client.Register(ctx, "ALICE", pass, pass, false); !errors.Is(err, service.ErrUsernameTaken) {
		t.Fatalf("another spelling of a taken name: error = %v", err)
	}

	if _, err := s.client.Register(ctx, "a-b", pass, pass, false); !errors.Is(err, service.ErrInvalidUsername) {
		t.Fatalf("a bad character: error = %v", err)
	}
}

func TestSignedRequestsCannotBeReplayedOverHTTP(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	pass := passphrase(t)

	if _, err := s.client.Register(ctx, "alice", pass, pass, false); err != nil {
		t.Fatal(err)
	}

	session, err := s.client.Login(ctx, "alice", pass)
	if err != nil {
		t.Fatal(err)
	}

	request := session.Sign("GET", wire.PathAccountBlobs, nil)

	blobs, err := s.transport.AccountBlobs(ctx, request)
	if err != nil || len(blobs) != 3 {
		t.Fatalf("first use: %d blobs, %v", len(blobs), err)
	}

	if _, err := s.transport.AccountBlobs(ctx, request); !errors.Is(err, service.ErrUnauthorized) {
		t.Fatalf("replay: error = %v, want ErrUnauthorized", err)
	}

	// A changed request keeps the old MAC and must fail too.
	changed := session.Sign("GET", wire.PathAccountBlobs, nil)
	changed.Path = wire.PathRecoveryBlob

	if _, err := s.transport.AccountBlobs(ctx, changed); !errors.Is(err, service.ErrUnauthorized) {
		t.Fatalf("changed path: error = %v, want ErrUnauthorized", err)
	}

	// And so does a request from nobody.
	forged := service.AuthRequest{
		SessionID: bytes.Repeat([]byte{9}, 32),
		Counter:   1,
		Method:    "GET",
		Path:      wire.PathAccountBlobs,
		MAC:       bytes.Repeat([]byte{1}, 32),
	}
	if _, err := s.transport.AccountBlobs(ctx, forged); !errors.Is(err, service.ErrUnauthorized) {
		t.Fatalf("forged request: error = %v, want ErrUnauthorized", err)
	}
}

func TestRecoverySessionCannotReadAccountBlobsOverHTTP(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	pass := passphrase(t)

	result, err := s.client.Register(ctx, "alice", pass, pass, true)
	if err != nil {
		t.Fatal(err)
	}

	// Log in the way a recovery would: the recovery kind, with the secret
	// derived from the phrase.
	key, err := recoverySecret(result.RecoveryPhrase)
	if err != nil {
		t.Fatal(err)
	}

	oc, err := auth.NewConfiguration().Client()
	if err != nil {
		t.Fatal(err)
	}

	challenge, err := s.transport.PowChallenge(ctx, "login", "alice")
	if err != nil {
		t.Fatal(err)
	}
	counter, err := pow.Solve(challenge, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	solution := &pow.Solution{
		Nonce:           challenge.Nonce,
		Difficulty:      challenge.Difficulty,
		IssuedAt:        challenge.IssuedAt,
		MAC:             challenge.MAC,
		SolutionCounter: counter,
	}

	start, err := s.transport.LoginStart(ctx, "alice", "recovery", oc.LoginInit(key).Serialize(), solution)
	if err != nil {
		t.Fatal(err)
	}

	ke2, err := oc.Deserialize.KE2(start.KE2)
	if err != nil {
		t.Fatal(err)
	}

	credentialID, err := recoveryCredentialID(start.UserID)
	if err != nil {
		t.Fatal(err)
	}

	ke3, _, err := oc.LoginFinish(ke2, opaque.ClientLoginFinishOptions{ClientIdentity: credentialID})
	if err != nil {
		t.Fatalf("recovery login: %v", err)
	}

	info, err := s.transport.LoginFinish(ctx, start.LoginID, ke3.Serialize())
	if err != nil {
		t.Fatal(err)
	}
	if info.Scope != "recovery" {
		t.Fatalf("scope = %q", info.Scope)
	}

	sessionRequestKey, err := requestKey(oc.SessionKey())
	if err != nil {
		t.Fatal(err)
	}

	request := signedRequest(sessionRequestKey, info.SessionID, 1, "GET", wire.PathAccountBlobs)
	if _, err := s.transport.AccountBlobs(ctx, request); !errors.Is(err, service.ErrUnauthorized) {
		t.Fatalf("a recovery session read the account blobs: error = %v", err)
	}
}

func TestLoginStartLooksTheSameForKnownAndUnknownUsers(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	pass := passphrase(t)

	if _, err := s.client.Register(ctx, "alice", pass, pass, false); err != nil {
		t.Fatal(err)
	}

	oc, err := auth.NewConfiguration().Client()
	if err != nil {
		t.Fatal(err)
	}
	ke1 := oc.LoginInit([]byte("some password")).Serialize()

	post := func(username string) (int, []byte, http.Header) {
		challenge, err := s.transport.PowChallenge(ctx, "login", username)
		if err != nil {
			t.Fatal(err)
		}
		counter, err := pow.Solve(challenge, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		solution := &wire.PowSolution{
			Nonce:           challenge.Nonce,
			Difficulty:      challenge.Difficulty,
			IssuedAt:        challenge.IssuedAt,
			MAC:             challenge.MAC,
			SolutionCounter: counter,
		}
		body, err := json.Marshal(wire.LoginStartRequest{Username: username, Kind: "password", KE1: ke1, Pow: solution})
		if err != nil {
			t.Fatal(err)
		}

		resp, err := http.Post(s.server.URL+wire.PathLoginStart, "application/json", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}

		return resp.StatusCode, data, resp.Header
	}

	knownStatus, knownBody, knownHeader := post("alice")
	unknownStatus, unknownBody, unknownHeader := post("mallory")

	if knownStatus != 200 || unknownStatus != 200 {
		t.Fatalf("statuses %d and %d", knownStatus, unknownStatus)
	}
	if len(knownBody) != len(unknownBody) {
		t.Fatalf("answer sizes differ: %d and %d", len(knownBody), len(unknownBody))
	}
	if knownHeader.Get("Content-Type") != unknownHeader.Get("Content-Type") ||
		knownHeader.Get("Cache-Control") != unknownHeader.Get("Cache-Control") {
		t.Fatal("the headers differ")
	}
}

func TestEveryAnswerCarriesTheSecurityHeaders(t *testing.T) {
	s := newStack(t)

	for _, target := range []string{wire.PathLoginStart, wire.PathAccountBlobs, "/nowhere"} {
		resp, err := http.Get(s.server.URL + target)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()

		if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: headers %v", target, resp.Header)
		}
	}
}

func TestChangePasswordOverHTTP(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	pass := passphrase(t)

	if _, err := s.client.Register(ctx, "alice", pass, pass, true); err != nil {
		t.Fatal(err)
	}

	session, err := s.client.Login(ctx, "alice", pass)
	if err != nil {
		t.Fatal(err)
	}

	stale := session.Sign("GET", wire.PathAccountBlobs, nil)

	const next = "Xq7#mP2$vL9@wR4!tN8z"

	fresh, err := s.client.ChangePassword(ctx, session, next, next)
	if err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	if _, err := s.client.Login(ctx, "alice", pass); !errors.Is(err, client.ErrLoginFailed) {
		t.Fatalf("old password: error = %v", err)
	}
	if _, err := s.client.Login(ctx, "alice", next); err != nil {
		t.Fatalf("new password: %v", err)
	}

	if _, err := s.transport.AccountBlobs(ctx, stale); !errors.Is(err, service.ErrUnauthorized) {
		t.Fatalf("old session: error = %v, want ErrUnauthorized", err)
	}
	if blobs, err := s.transport.AccountBlobs(ctx, fresh.Sign("GET", wire.PathAccountBlobs, nil)); err != nil || len(blobs) != 3 {
		t.Fatalf("new session: %d blobs, %v", len(blobs), err)
	}
}

func TestPinningOverHTTP(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	pass := passphrase(t)

	pins := client.NewMemPins()
	c := client.New(s.transport, client.NewMemHeads(), pins)

	if _, err := c.Register(ctx, "alice", pass, pass, false); err != nil {
		t.Fatal(err)
	}

	pinned, ok := pins.Get()
	if !ok || len(pinned) == 0 {
		t.Fatal("registration did not pin the key")
	}

	if _, err := c.Login(ctx, "alice", pass); err != nil {
		t.Fatalf("login after pin: %v", err)
	}

	// A different device that pins a different key must be refused.
	wrong := client.New(s.transport, client.NewMemHeads(), client.NewMemPins())
	wrong.Pins.Put(bytes.Repeat([]byte{0x99}, 32))
	if _, err := wrong.Login(ctx, "alice", pass); !errors.Is(err, client.ErrServerKeyChanged) {
		t.Fatalf("error = %v, want ErrServerKeyChanged", err)
	}
}

func TestStalePinDoesNotBlockTheNameOverHTTP(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	pass := passphrase(t)

	stale := client.New(s.transport, client.NewMemHeads(), client.NewMemPins())
	stale.Pins.Put([]byte("not the real server key"))
	if _, err := stale.Register(ctx, "alice", pass, pass, false); !errors.Is(err, client.ErrServerKeyChanged) {
		t.Fatalf("error = %v, want ErrServerKeyChanged", err)
	}

	if _, err := s.client.Register(ctx, "alice", pass, pass, false); err != nil {
		t.Fatalf("register after failed pin check: %v", err)
	}
}
