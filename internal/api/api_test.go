// File: internal/api/api_test.go

package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/pow"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/wire"
)

var errNotSet = errors.New("stub function not set")

// stubService lets a test replace single service methods. A method that was
// not set returns an error.
type stubService struct {
	registerStart  func(context.Context, string, []byte, []byte, *pow.Solution) (service.RegisterStartResult, error)
	powChallenge   func(context.Context, string, string) (pow.Challenge, error)
	serverInfo     func(context.Context) (service.ServerInfoResult, error)
	registerFinish func(context.Context, service.RegisterFinishRequest) error
	loginStart     func(context.Context, string, string, []byte, *pow.Solution) (service.LoginStartResult, error)
	loginFinish    func(context.Context, []byte, []byte) (service.SessionInfo, error)
	authenticate   func(context.Context, service.AuthRequest, string) (store.Session, error)
	currentBlobs   func(context.Context, []byte, ...byte) ([]service.BlobInfo, error)

	passwordStart         func(context.Context, []byte, []byte) ([]byte, error)
	passwordBegin         func(context.Context, []byte, uint64, []byte, service.BlobUpload) error
	recoveryView          func(context.Context, []byte) (service.RecoveryViewResult, error)
	recoveryPasswordStart func(context.Context, []byte, []byte) ([]byte, error)
	recoveryPasswordBegin func(context.Context, []byte, uint64, []byte, service.BlobUpload) error
	recoveryRotateStart   func(context.Context, []byte, []byte) ([]byte, error)
	recoveryRotateBegin   func(context.Context, []byte, uint64, []byte, service.BlobUpload) error
	recoveryDisable       func(context.Context, []byte) error
}

func (s *stubService) RegisterStart(ctx context.Context, username string, p, r []byte, solution *pow.Solution) (service.RegisterStartResult, error) {
	if s.registerStart == nil {
		return service.RegisterStartResult{}, errNotSet
	}
	return s.registerStart(ctx, username, p, r, solution)
}

func (s *stubService) RegisterFinish(ctx context.Context, r service.RegisterFinishRequest) error {
	if s.registerFinish == nil {
		return errNotSet
	}
	return s.registerFinish(ctx, r)
}

func (s *stubService) LoginStart(ctx context.Context, username, kind string, ke1 []byte, solution *pow.Solution) (service.LoginStartResult, error) {
	if s.loginStart == nil {
		return service.LoginStartResult{}, errNotSet
	}
	return s.loginStart(ctx, username, kind, ke1, solution)
}

func (s *stubService) LoginFinish(ctx context.Context, loginID, ke3 []byte) (service.SessionInfo, error) {
	if s.loginFinish == nil {
		return service.SessionInfo{}, errNotSet
	}
	return s.loginFinish(ctx, loginID, ke3)
}

func (s *stubService) Authenticate(ctx context.Context, r service.AuthRequest, scope string) (store.Session, error) {
	if s.authenticate == nil {
		return store.Session{}, errNotSet
	}
	return s.authenticate(ctx, r, scope)
}

func (s *stubService) CurrentBlobs(ctx context.Context, userID []byte, kinds ...byte) ([]service.BlobInfo, error) {
	if s.currentBlobs == nil {
		return nil, errNotSet
	}
	return s.currentBlobs(ctx, userID, kinds...)
}

func serve(h http.Handler, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}

func post(t *testing.T, h http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()

	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	return serve(h, "POST", path, string(encoded), map[string]string{
		"Content-Type": "application/json",
	})
}

func errorCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()

	var e wire.ErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatalf("body is not an error response: %q", rec.Body.String())
	}

	return e.Error
}

func signedHeaders(session, mac []byte, counter uint64) map[string]string {
	return map[string]string{
		wire.HeaderSession: base64.StdEncoding.EncodeToString(session),
		wire.HeaderCounter: strconv.FormatUint(counter, 10),
		wire.HeaderMAC:     base64.StdEncoding.EncodeToString(mac),
	}
}

func TestRegisterStartPassesDataThrough(t *testing.T) {
	var gotUser string
	var gotPassword, gotRecovery []byte

	svc := &stubService{
		registerStart: func(_ context.Context, username string, p, r []byte, _ *pow.Solution) (service.RegisterStartResult, error) {
			gotUser, gotPassword, gotRecovery = username, p, r
			return service.RegisterStartResult{
				UserID:           []byte{1},
				PasswordResponse: []byte{2},
				RecoveryResponse: []byte{3},
			}, nil
		},
	}

	rec := post(t, New(svc, nil), wire.PathRegisterStart, wire.RegisterStartRequest{
		Username:        "alice",
		PasswordRequest: []byte{7, 7},
		RecoveryRequest: []byte{8, 8},
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}

	var res wire.RegisterStartResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}

	if gotUser != "alice" ||
		!bytes.Equal(gotPassword, []byte{7, 7}) ||
		!bytes.Equal(gotRecovery, []byte{8, 8}) {
		t.Fatalf("service saw %q %x %x", gotUser, gotPassword, gotRecovery)
	}
	if !bytes.Equal(res.UserID, []byte{1}) ||
		!bytes.Equal(res.PasswordResponse, []byte{2}) ||
		!bytes.Equal(res.RecoveryResponse, []byte{3}) {
		t.Fatalf("unexpected response %+v", res)
	}
}

func TestRegisterFinishGivesNoContent(t *testing.T) {
	var got service.RegisterFinishRequest

	svc := &stubService{
		registerFinish: func(_ context.Context, r service.RegisterFinishRequest) error {
			got = r
			return nil
		},
	}

	rec := post(t, New(svc, nil), wire.PathRegisterFinish, wire.RegisterFinishRequest{
		UserID:         bytes.Repeat([]byte{1}, 16),
		Username:       "alice",
		PasswordRecord: []byte("record"),
		Blobs: []wire.Blob{
			{Kind: 1, Version: 1, PrevHash: make([]byte, 32), Data: []byte("kek")},
		},
		PublicKeys: []wire.PublicKey{{Kind: "sign", Key: []byte("key")}},
	})

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("a 204 response has a body: %q", rec.Body.String())
	}
	if got.Username != "alice" || len(got.Blobs) != 1 || len(got.PublicKeys) != 1 {
		t.Fatalf("service saw %+v", got)
	}
}

func TestRegisterFinishRefusesShortHashes(t *testing.T) {
	svc := &stubService{
		registerFinish: func(context.Context, service.RegisterFinishRequest) error {
			t.Error("the service was called")
			return nil
		},
	}

	rec := post(t, New(svc, nil), wire.PathRegisterFinish, wire.RegisterFinishRequest{
		Username: "alice",
		Blobs:    []wire.Blob{{Kind: 1, Version: 1, PrevHash: []byte{1, 2, 3}}},
	})

	if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
}

func TestLoginRoundTrip(t *testing.T) {
	var gotKind string
	var gotKE3 []byte

	svc := &stubService{
		loginStart: func(_ context.Context, _ string, kind string, _ []byte, _ *pow.Solution) (service.LoginStartResult, error) {
			gotKind = kind
			return service.LoginStartResult{LoginID: []byte{1}, UserID: []byte{2}, KE2: []byte{3}}, nil
		},
		loginFinish: func(_ context.Context, _ []byte, ke3 []byte) (service.SessionInfo, error) {
			gotKE3 = ke3
			return service.SessionInfo{SessionID: []byte{4}, UserID: []byte{5}, Scope: "full"}, nil
		},
	}

	h := New(svc, nil)

	rec := post(t, h, wire.PathLoginStart, wire.LoginStartRequest{
		Username: "alice", Kind: "recovery", KE1: []byte{9},
	})
	var start wire.LoginStartResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &start) != nil {
		t.Fatalf("login start: status %d, body %s", rec.Code, rec.Body.String())
	}
	if gotKind != "recovery" || !bytes.Equal(start.KE2, []byte{3}) {
		t.Fatalf("kind %q, response %+v", gotKind, start)
	}

	rec = post(t, h, wire.PathLoginFinish, wire.LoginFinishRequest{LoginID: []byte{1}, KE3: []byte{6}})
	var finish wire.LoginFinishResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &finish) != nil {
		t.Fatalf("login finish: status %d, body %s", rec.Code, rec.Body.String())
	}
	if !bytes.Equal(gotKE3, []byte{6}) || finish.Scope != "full" || !bytes.Equal(finish.SessionID, []byte{4}) {
		t.Fatalf("ke3 %x, response %+v", gotKE3, finish)
	}
}

func TestErrorMapping(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
		code   string
	}{
		{"login failed", service.ErrLoginFailed, 401, "unauthorized"},
		{"unauthorized", service.ErrUnauthorized, 401, "unauthorized"},
		{"invalid username", service.ErrInvalidUsername, 400, "invalid_username"},
		{"invalid request", service.ErrInvalidRequest, 400, "invalid_request"},
		{"username taken", service.ErrUsernameTaken, 409, "username_taken"},
		{"conflict", service.ErrConflict, 409, "conflict"},
		{"internal", service.ErrInternal, 500, "internal"},
		{"wrapped", fmt.Errorf("context: %w", service.ErrLoginFailed), 401, "unauthorized"},
		{"unexpected", errors.New("db connection failed, password=hunter2"), 500, "internal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &stubService{
				loginStart: func(context.Context, string, string, []byte, *pow.Solution) (service.LoginStartResult, error) {
					return service.LoginStartResult{}, tt.err
				},
			}

			var logs bytes.Buffer
			h := New(svc, log.New(&logs, "", 0))

			rec := post(t, h, wire.PathLoginStart, wire.LoginStartRequest{Username: "alice", Kind: "password"})

			if rec.Code != tt.status {
				t.Fatalf("status = %d, want %d", rec.Code, tt.status)
			}
			if got := errorCode(t, rec); got != tt.code {
				t.Fatalf("code = %q, want %q", got, tt.code)
			}
			if strings.Contains(rec.Body.String(), "hunter2") {
				t.Fatal("the response leaks the internal error")
			}
		})
	}
}

func TestFailedLoginAndFailedAuthenticationLookTheSame(t *testing.T) {
	svc := &stubService{
		loginFinish: func(context.Context, []byte, []byte) (service.SessionInfo, error) {
			return service.SessionInfo{}, service.ErrLoginFailed
		},
		authenticate: func(context.Context, service.AuthRequest, string) (store.Session, error) {
			return store.Session{}, service.ErrUnauthorized
		},
	}

	h := New(svc, nil)

	first := post(t, h, wire.PathLoginFinish, wire.LoginFinishRequest{LoginID: []byte{1}, KE3: []byte{2}})
	second := serve(h, "GET", wire.PathAccountBlobs, "", signedHeaders([]byte{1}, []byte{2}, 1))

	if first.Code != second.Code || first.Body.String() != second.Body.String() {
		t.Fatalf("different answers: %d %q and %d %q",
			first.Code, first.Body.String(), second.Code, second.Body.String())
	}
}

func TestContentTypeIsChecked(t *testing.T) {
	svc := &stubService{
		loginStart: func(context.Context, string, string, []byte, *pow.Solution) (service.LoginStartResult, error) {
			return service.LoginStartResult{}, nil
		},
	}
	h := New(svc, nil)
	body := `{"username":"alice","kind":"password","ke1":"AQ=="}`

	for _, contentType := range []string{"", "text/plain", "application/x-www-form-urlencoded", "application/jsonx"} {
		rec := serve(h, "POST", wire.PathLoginStart, body, map[string]string{"Content-Type": contentType})
		if rec.Code != http.StatusUnsupportedMediaType || errorCode(t, rec) != "unsupported_media_type" {
			t.Fatalf("content type %q: status %d, body %s", contentType, rec.Code, rec.Body.String())
		}
	}

	rec := serve(h, "POST", wire.PathLoginStart, body, map[string]string{
		"Content-Type": "application/json; charset=utf-8",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("with a charset: status %d, body %s", rec.Code, rec.Body.String())
	}
}

func TestBadJSONIsRefused(t *testing.T) {
	svc := &stubService{
		loginStart: func(context.Context, string, string, []byte, *pow.Solution) (service.LoginStartResult, error) {
			t.Error("the service was called")
			return service.LoginStartResult{}, nil
		},
	}
	h := New(svc, nil)

	bodies := map[string]string{
		"unknown field":      `{"username":"a","kind":"password","ke1":"AQ==","extra":1}`,
		"two values":         `{"username":"a"} {"username":"b"}`,
		"not json":           `not json`,
		"empty":              ``,
		"wrong type":         `{"username":5}`,
		"bad base64":         `{"username":"a","ke1":"!!!"}`,
		"array":              `[1,2,3]`,
		"trailing garbage":   `{"username":"a"} xyz`,
		"null bytes content": "{\"username\":\"a\x00\"}",
	}

	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			rec := serve(h, "POST", wire.PathLoginStart, body, map[string]string{"Content-Type": "application/json"})
			if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestOversizedBodyIsRefused(t *testing.T) {
	svc := &stubService{
		loginStart: func(context.Context, string, string, []byte, *pow.Solution) (service.LoginStartResult, error) {
			t.Error("the service was called")
			return service.LoginStartResult{}, nil
		},
	}

	body := `{"username":"` + strings.Repeat("a", 70<<10) + `"}`
	rec := serve(New(svc, nil), "POST", wire.PathLoginStart, body, map[string]string{"Content-Type": "application/json"})

	if rec.Code != http.StatusRequestEntityTooLarge || errorCode(t, rec) != "too_large" {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
}

func TestWrongMethodAndUnknownPath(t *testing.T) {
	h := New(&stubService{}, nil)

	if rec := serve(h, "GET", wire.PathLoginStart, "", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET on a POST route: status %d", rec.Code)
	}
	if rec := serve(h, "POST", wire.PathAccountBlobs, "", nil); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST on a GET route: status %d", rec.Code)
	}
	if rec := serve(h, "POST", "/v1/nothing", "", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown path: status %d", rec.Code)
	}
}

func TestResponsesAreNeverCached(t *testing.T) {
	svc := &stubService{
		loginStart: func(context.Context, string, string, []byte, *pow.Solution) (service.LoginStartResult, error) {
			return service.LoginStartResult{LoginID: []byte{1}}, nil
		},
	}
	h := New(svc, nil)

	good := post(t, h, wire.PathLoginStart, wire.LoginStartRequest{Username: "alice", Kind: "password"})
	bad := serve(h, "POST", wire.PathLoginStart, "x", nil)
	missing := serve(h, "GET", "/nowhere", "", nil)

	for name, rec := range map[string]*httptest.ResponseRecorder{"success": good, "error": bad, "not found": missing} {
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("%s: Cache-Control = %q", name, got)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Fatalf("%s: X-Content-Type-Options = %q", name, got)
		}
	}
}

func TestSignatureHeadersMustBeWellFormed(t *testing.T) {
	svc := &stubService{
		authenticate: func(context.Context, service.AuthRequest, string) (store.Session, error) {
			t.Error("the service was called")
			return store.Session{}, nil
		},
	}
	h := New(svc, nil)

	valid := signedHeaders([]byte{1}, []byte{2}, 1)

	with := func(key, value string) map[string]string {
		headers := map[string]string{}
		for k, v := range valid {
			headers[k] = v
		}
		headers[key] = value
		return headers
	}

	tests := map[string]map[string]string{
		"no headers":              nil,
		"session not base64":      with(wire.HeaderSession, "!!!"),
		"empty session":           with(wire.HeaderSession, ""),
		"mac not base64":          with(wire.HeaderMAC, "!!!"),
		"empty mac":               with(wire.HeaderMAC, ""),
		"counter not a number":    with(wire.HeaderCounter, "abc"),
		"negative counter":        with(wire.HeaderCounter, "-1"),
		"counter too large":       with(wire.HeaderCounter, "99999999999999999999"),
		"counter with whitespace": with(wire.HeaderCounter, " 1"),
	}

	for name, headers := range tests {
		t.Run(name, func(t *testing.T) {
			for _, path := range []string{wire.PathAccountBlobs, wire.PathRecoveryBlob} {
				rec := serve(h, "GET", path, "", headers)
				if rec.Code != http.StatusUnauthorized || errorCode(t, rec) != "unauthorized" {
					t.Fatalf("%s: status %d, body %s", path, rec.Code, rec.Body.String())
				}
			}
		})
	}
}

func TestQueryStringsAreRefusedOnSignedRoutes(t *testing.T) {
	svc := &stubService{
		authenticate: func(context.Context, service.AuthRequest, string) (store.Session, error) {
			t.Error("the service was called")
			return store.Session{}, nil
		},
	}

	rec := serve(New(svc, nil), "GET", wire.PathAccountBlobs+"?x=1", "", signedHeaders([]byte{1}, []byte{2}, 1))

	if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
}

func TestSignedRequestsReachTheServiceExactly(t *testing.T) {
	var gotRequest service.AuthRequest
	var gotScope string
	var gotUser, gotKinds, gotViewUser []byte

	svc := &stubService{
		authenticate: func(_ context.Context, r service.AuthRequest, scope string) (store.Session, error) {
			gotRequest, gotScope = r, scope
			return store.Session{UserID: []byte{7, 7}}, nil
		},
		currentBlobs: func(_ context.Context, userID []byte, kinds ...byte) ([]service.BlobInfo, error) {
			gotUser, gotKinds = userID, kinds
			return []service.BlobInfo{
				{Kind: kinds[0], Version: 3, PrevHash: [32]byte{1}, Data: []byte("data")},
			}, nil
		},
		recoveryView: func(_ context.Context, userID []byte) (service.RecoveryViewResult, error) {
			gotViewUser = userID
			return service.RecoveryViewResult{
				Recovery:  service.BlobInfo{Kind: store.BlobKindRecovery, Version: 1, Data: []byte("rec")},
				KEKHeader: service.BlobHeader{Version: 2, Hash: [32]byte{3}},
			}, nil
		},
	}

	h := New(svc, nil)
	headers := signedHeaders([]byte{1, 2, 3}, []byte{4, 5, 6}, 42)

	rec := serve(h, "GET", wire.PathAccountBlobs, "hello", headers)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}

	if gotScope != "full" ||
		gotRequest.Method != "GET" ||
		gotRequest.Path != wire.PathAccountBlobs ||
		gotRequest.Counter != 42 ||
		string(gotRequest.Body) != "hello" ||
		!bytes.Equal(gotRequest.SessionID, []byte{1, 2, 3}) ||
		!bytes.Equal(gotRequest.MAC, []byte{4, 5, 6}) {
		t.Fatalf("service saw scope %q and %+v", gotScope, gotRequest)
	}

	wantKinds := []byte{store.BlobKindKEK, store.BlobKindMEK, store.BlobKindIdentity}
	if !bytes.Equal(gotUser, []byte{7, 7}) || !bytes.Equal(gotKinds, wantKinds) {
		t.Fatalf("blobs asked for user %x kinds %x", gotUser, gotKinds)
	}

	var res wire.BlobsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Blobs) != 1 || res.Blobs[0].Version != 3 || len(res.Blobs[0].PrevHash) != 32 {
		t.Fatalf("unexpected response %+v", res)
	}

	// The recovery route now goes through RecoveryView, not CurrentBlobs.
	rec = serve(h, "GET", wire.PathRecoveryBlob, "", headers)
	if rec.Code != http.StatusOK {
		t.Fatalf("recovery route: status %d, body %s", rec.Code, rec.Body.String())
	}
	if gotScope != "recovery" || gotRequest.Path != wire.PathRecoveryBlob {
		t.Fatalf("recovery route used scope %q and path %q", gotScope, gotRequest.Path)
	}
	if !bytes.Equal(gotViewUser, []byte{7, 7}) {
		t.Fatalf("recovery view asked for user %x", gotViewUser)
	}

	var rres wire.RecoveryBlobsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &rres); err != nil {
		t.Fatal(err)
	}
	if len(rres.Blobs) != 1 || rres.KEKHeader.Version != 2 {
		t.Fatalf("unexpected recovery response %+v", rres)
	}
}

func TestRefusedAuthenticationReturnsNoData(t *testing.T) {
	svc := &stubService{
		authenticate: func(context.Context, service.AuthRequest, string) (store.Session, error) {
			return store.Session{}, service.ErrUnauthorized
		},
		currentBlobs: func(context.Context, []byte, ...byte) ([]service.BlobInfo, error) {
			t.Error("blobs were read for an unauthenticated request")
			return nil, nil
		},
	}

	rec := serve(New(svc, nil), "GET", wire.PathAccountBlobs, "", signedHeaders([]byte{1}, []byte{2}, 1))

	if rec.Code != http.StatusUnauthorized || rec.Body.String() != `{"error":"unauthorized"}` {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
}

func (s *stubService) PasswordChangeStart(ctx context.Context, userID, request []byte) ([]byte, error) {
	if s.passwordStart == nil {
		return nil, errNotSet
	}
	return s.passwordStart(ctx, userID, request)
}

func (s *stubService) PasswordChangeBegin(ctx context.Context, userID []byte, expectedVersion uint64, record []byte, kek service.BlobUpload) error {
	if s.passwordBegin == nil {
		return errNotSet
	}
	return s.passwordBegin(ctx, userID, expectedVersion, record, kek)
}

func (s *stubService) RecoveryView(ctx context.Context, userID []byte) (service.RecoveryViewResult, error) {
	if s.recoveryView == nil {
		return service.RecoveryViewResult{}, errNotSet
	}
	return s.recoveryView(ctx, userID)
}

func (s *stubService) RecoveryPasswordStart(ctx context.Context, userID, passwordReq []byte) ([]byte, error) {
	if s.recoveryPasswordStart == nil {
		return nil, errNotSet
	}
	return s.recoveryPasswordStart(ctx, userID, passwordReq)
}

func (s *stubService) RecoveryPasswordBegin(ctx context.Context, userID []byte, expectedVersion uint64, record []byte, kek service.BlobUpload) error {
	if s.recoveryPasswordBegin == nil {
		return errNotSet
	}
	return s.recoveryPasswordBegin(ctx, userID, expectedVersion, record, kek)
}

func (s *stubService) RecoveryRotateStart(ctx context.Context, userID, recoveryReq []byte) ([]byte, error) {
	if s.recoveryRotateStart == nil {
		return nil, errNotSet
	}
	return s.recoveryRotateStart(ctx, userID, recoveryReq)
}

func (s *stubService) RecoveryRotateBegin(ctx context.Context, userID []byte, expectedVersion uint64, record []byte, blob service.BlobUpload) error {
	if s.recoveryRotateBegin == nil {
		return errNotSet
	}
	return s.recoveryRotateBegin(ctx, userID, expectedVersion, record, blob)
}

func (s *stubService) RecoveryDisable(ctx context.Context, userID []byte) error {
	if s.recoveryDisable == nil {
		return errNotSet
	}
	return s.recoveryDisable(ctx, userID)
}

// signedJSON posts a JSON body with signature headers.
func signedJSON(t *testing.T, h http.Handler, path string, body any, extra map[string]string) (*httptest.ResponseRecorder, string) {
	t.Helper()

	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}

	headers := signedHeaders([]byte{1}, []byte{2}, 1)
	headers["Content-Type"] = "application/json"
	for key, value := range extra {
		headers[key] = value
	}

	return serve(h, "POST", path, string(encoded), headers), string(encoded)
}

func authenticatedAs(userID []byte, seen *service.AuthRequest, scope *string) func(context.Context, service.AuthRequest, string) (store.Session, error) {
	return func(_ context.Context, r service.AuthRequest, s string) (store.Session, error) {
		if seen != nil {
			*seen = r
		}
		if scope != nil {
			*scope = s
		}
		return store.Session{UserID: userID}, nil
	}
}

func TestPasswordRoutesNeedASignature(t *testing.T) {
	svc := &stubService{
		passwordStart: func(context.Context, []byte, []byte) ([]byte, error) {
			t.Error("the service was called")
			return nil, nil
		},
		passwordBegin: func(context.Context, []byte, uint64, []byte, service.BlobUpload) error {
			t.Error("the service was called")
			return nil
		},
	}
	h := New(svc, nil)

	for _, path := range []string{wire.PathPasswordStart, wire.PathPasswordBegin} {
		rec := serve(h, "POST", path, "{}", map[string]string{"Content-Type": "application/json"})
		if rec.Code != http.StatusUnauthorized || errorCode(t, rec) != "unauthorized" {
			t.Fatalf("%s: status %d, body %s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestPasswordStartPassesTheRequest(t *testing.T) {
	var seen service.AuthRequest
	var scope string
	var gotUser, gotRequest []byte

	svc := &stubService{
		authenticate: authenticatedAs([]byte{7}, &seen, &scope),
		passwordStart: func(_ context.Context, userID, request []byte) ([]byte, error) {
			gotUser, gotRequest = userID, request
			return []byte{5}, nil
		},
	}

	rec, sent := signedJSON(t, New(svc, nil), wire.PathPasswordStart, wire.PasswordStartRequest{PasswordRequest: []byte{1, 2}}, nil)

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}

	var res wire.PasswordStartResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}

	if scope != "full" || string(seen.Body) != sent || seen.Path != wire.PathPasswordStart || seen.Method != "POST" {
		t.Fatalf("authenticated as scope %q with %+v", scope, seen)
	}
	if !bytes.Equal(gotUser, []byte{7}) || !bytes.Equal(gotRequest, []byte{1, 2}) || !bytes.Equal(res.PasswordResponse, []byte{5}) {
		t.Fatalf("service saw %x %x, answer %+v", gotUser, gotRequest, res)
	}
}

func TestPasswordBeginPassesTheRequest(t *testing.T) {
	var gotVersion uint64
	var gotRecord []byte
	var gotKEK service.BlobUpload

	svc := &stubService{
		authenticate: authenticatedAs([]byte{7}, nil, nil),
		passwordBegin: func(_ context.Context, _ []byte, expected uint64, record []byte, kek service.BlobUpload) error {
			gotVersion, gotRecord, gotKEK = expected, record, kek
			return nil
		},
	}

	rec, _ := signedJSON(t, New(svc, nil), wire.PathPasswordBegin, wire.PasswordBeginRequest{
		ExpectedVersion: 3,
		Record:          []byte{1},
		KEK:             wire.Blob{Kind: 1, Version: 4, PrevHash: make([]byte, 32), Data: []byte("kek")},
	}, nil)

	if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
		t.Fatalf("status %d, body %q", rec.Code, rec.Body.String())
	}
	if gotVersion != 3 || !bytes.Equal(gotRecord, []byte{1}) || gotKEK.Version != 4 || gotKEK.Kind != 1 {
		t.Fatalf("service saw %d %x %+v", gotVersion, gotRecord, gotKEK)
	}
}

func TestPasswordBeginRefusesShortHashes(t *testing.T) {
	svc := &stubService{
		authenticate: authenticatedAs([]byte{7}, nil, nil),
		passwordBegin: func(context.Context, []byte, uint64, []byte, service.BlobUpload) error {
			t.Error("the service was called")
			return nil
		},
	}

	rec, _ := signedJSON(t, New(svc, nil), wire.PathPasswordBegin, wire.PasswordBeginRequest{
		ExpectedVersion: 1,
		KEK:             wire.Blob{Kind: 1, Version: 2, PrevHash: []byte{1, 2, 3}},
	}, nil)

	if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
}

func TestSignedBodiesFollowTheSameRules(t *testing.T) {
	svc := &stubService{
		authenticate: authenticatedAs([]byte{7}, nil, nil),
		passwordStart: func(context.Context, []byte, []byte) ([]byte, error) {
			t.Error("the service was called")
			return nil, nil
		},
	}
	h := New(svc, nil)

	headers := signedHeaders([]byte{1}, []byte{2}, 1)

	bodies := map[string]string{
		"unknown field": `{"password_request":"AQ==","extra":1}`,
		"two values":    `{"password_request":"AQ=="} {}`,
		"not json":      `nope`,
		"empty":         ``,
		"bad base64":    `{"password_request":"!!!"}`,
	}

	for name, body := range bodies {
		all := map[string]string{"Content-Type": "application/json"}
		for key, value := range headers {
			all[key] = value
		}

		rec := serve(h, "POST", wire.PathPasswordStart, body, all)
		if rec.Code != http.StatusBadRequest || errorCode(t, rec) != "invalid_request" {
			t.Fatalf("%s: status %d, body %s", name, rec.Code, rec.Body.String())
		}
	}

	rec := serve(h, "POST", wire.PathPasswordStart, `{"password_request":"AQ=="}`, headers)
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("without a content type: status %d", rec.Code)
	}
}

func TestAChangeThatClashesIsReported(t *testing.T) {
	svc := &stubService{
		authenticate: authenticatedAs([]byte{7}, nil, nil),
		passwordBegin: func(context.Context, []byte, uint64, []byte, service.BlobUpload) error {
			return service.ErrConflict
		},
	}

	rec, _ := signedJSON(t, New(svc, nil), wire.PathPasswordBegin, wire.PasswordBeginRequest{
		ExpectedVersion: 1,
		KEK:             wire.Blob{Kind: 1, Version: 2, PrevHash: make([]byte, 32)},
	}, nil)

	if rec.Code != http.StatusConflict || errorCode(t, rec) != "conflict" {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
}

func TestRecoveryBlobReturnsTheKEKHeader(t *testing.T) {
	svc := &stubService{
		authenticate: authenticatedAs([]byte{7}, nil, nil),
		recoveryView: func(_ context.Context, userID []byte) (service.RecoveryViewResult, error) {
			if !bytes.Equal(userID, []byte{7}) {
				t.Fatalf("user %x", userID)
			}
			return service.RecoveryViewResult{
				Recovery: service.BlobInfo{Kind: 4, Version: 1, Data: []byte("rec")},
				KEKHeader: service.BlobHeader{
					Version:  3,
					PrevHash: [32]byte{1},
					Hash:     [32]byte{2},
				},
			}, nil
		},
	}

	rec := serve(New(svc, nil), "GET", wire.PathRecoveryBlob, "", signedHeaders([]byte{1}, []byte{2}, 1))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}

	var res wire.RecoveryBlobsResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Blobs) != 1 || res.KEKHeader.Version != 3 || len(res.KEKHeader.Hash) != 32 {
		t.Fatalf("unexpected response %+v", res)
	}
}

func (s *stubService) PowChallenge(ctx context.Context, purpose, username string) (pow.Challenge, error) {
	if s.powChallenge == nil {
		return pow.Challenge{}, errNotSet
	}
	return s.powChallenge(ctx, purpose, username)
}

func (s *stubService) ServerInfo(ctx context.Context) (service.ServerInfoResult, error) {
	if s.serverInfo == nil {
		return service.ServerInfoResult{}, errNotSet
	}
	return s.serverInfo(ctx)
}

func TestServerInfoReturnsTheKey(t *testing.T) {
	svc := &stubService{
		serverInfo: func(context.Context) (service.ServerInfoResult, error) {
			return service.ServerInfoResult{PublicKey: []byte{1, 2, 3}}, nil
		},
	}

	rec := serve(New(svc, nil), "GET", wire.PathServerInfo, "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}

	var res wire.ServerInfoResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(res.ServerPublicKey, []byte{1, 2, 3}) {
		t.Fatalf("key %x", res.ServerPublicKey)
	}
}
