// File: client/httptransport/httptransport_test.go

package httptransport

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.com/sherlockholmesat221b/nanogram/client"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/wire"
)

func answer(status int, body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	})
}

func TestStatusMapping(t *testing.T) {
	ctx := context.Background()
	signed := service.AuthRequest{
		SessionID: []byte{1}, Counter: 1, Method: "GET", Path: wire.PathAccountBlobs, MAC: []byte{2},
	}

	tests := []struct {
		name   string
		status int
		body   string
		call   func(*Transport) error
		want   error
	}{
		{"login start, 401", 401, `{"error":"unauthorized"}`, func(t *Transport) error {
			_, err := t.LoginStart(ctx, "alice", "password", []byte{1})
			return err
		}, service.ErrLoginFailed},
		{"login finish, 401", 401, `{"error":"unauthorized"}`, func(t *Transport) error {
			_, err := t.LoginFinish(ctx, []byte{1}, []byte{2})
			return err
		}, service.ErrLoginFailed},
		{"signed request, 401", 401, `{"error":"unauthorized"}`, func(t *Transport) error {
			_, err := t.AccountBlobs(ctx, signed)
			return err
		}, service.ErrUnauthorized},
		{"username taken", 409, `{"error":"username_taken"}`, func(t *Transport) error {
			_, err := t.RegisterStart(ctx, "alice", []byte{1}, nil)
			return err
		}, service.ErrUsernameTaken},
		{"invalid username", 400, `{"error":"invalid_username"}`, func(t *Transport) error {
			_, err := t.RegisterStart(ctx, "A", []byte{1}, nil)
			return err
		}, service.ErrInvalidUsername},
		{"invalid request", 400, `{"error":"invalid_request"}`, func(t *Transport) error {
			_, err := t.LoginStart(ctx, "alice", "password", []byte{1})
			return err
		}, service.ErrInvalidRequest},
		{"too large", 413, `{"error":"too_large"}`, func(t *Transport) error {
			_, err := t.LoginStart(ctx, "alice", "password", []byte{1})
			return err
		}, service.ErrInvalidRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(answer(tt.status, tt.body))
			defer srv.Close()

			if err := tt.call(New(srv.URL, srv.Client())); !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestOtherFailuresAreGeneric(t *testing.T) {
	for _, status := range []int{500, 503, 404, 302} {
		srv := httptest.NewServer(answer(status, "secret text from the server"))

		_, err := New(srv.URL, srv.Client()).LoginStart(context.Background(), "alice", "password", []byte{1})
		srv.Close()

		if err == nil {
			t.Fatalf("status %d: no error", status)
		}
		if strings.Contains(err.Error(), "secret text") {
			t.Fatalf("status %d: the server's text is in the error: %v", status, err)
		}
		for _, sentinel := range []error{service.ErrLoginFailed, service.ErrUnauthorized, service.ErrUsernameTaken} {
			if errors.Is(err, sentinel) {
				t.Fatalf("status %d was mapped to %v", status, sentinel)
			}
		}
	}
}

func TestLoginStartSendsJSONAndReadsTheAnswer(t *testing.T) {
	var gotType string
	var got wire.LoginStartRequest

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotType = r.Header.Get("Content-Type")
		if r.Method != "POST" || r.URL.Path != wire.PathLoginStart {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)

		_ = json.NewEncoder(w).Encode(wire.LoginStartResponse{
			LoginID: []byte{1}, UserID: []byte{2}, KE2: []byte{3},
		})
	}))
	defer srv.Close()

	res, err := New(srv.URL+"/", srv.Client()).LoginStart(context.Background(), "alice", "recovery", []byte{9})
	if err != nil {
		t.Fatal(err)
	}

	if gotType != "application/json" || got.Username != "alice" || got.Kind != "recovery" || len(got.KE1) != 1 {
		t.Fatalf("server saw %q %+v", gotType, got)
	}
	if res.LoginID[0] != 1 || res.UserID[0] != 2 || res.KE2[0] != 3 {
		t.Fatalf("answer %+v", res)
	}
}

func TestSignedRequestIsSentExactly(t *testing.T) {
	var method, path, session, counter, mac, body string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		session = r.Header.Get(wire.HeaderSession)
		counter = r.Header.Get(wire.HeaderCounter)
		mac = r.Header.Get(wire.HeaderMAC)
		data, _ := io.ReadAll(r.Body)
		body = string(data)

		_ = json.NewEncoder(w).Encode(wire.BlobsResponse{Blobs: []wire.Blob{
			{Kind: 1, Version: 2, PrevHash: make([]byte, 32), Data: []byte("x")},
		}})
	}))
	defer srv.Close()

	blobs, err := New(srv.URL, srv.Client()).AccountBlobs(context.Background(), service.AuthRequest{
		SessionID: []byte{1, 2, 3},
		Counter:   42,
		Method:    "GET",
		Path:      wire.PathAccountBlobs,
		Body:      []byte("body"),
		MAC:       []byte{4, 5, 6},
	})
	if err != nil {
		t.Fatal(err)
	}

	if method != "GET" || path != wire.PathAccountBlobs || body != "body" || counter != "42" ||
		session != base64.StdEncoding.EncodeToString([]byte{1, 2, 3}) ||
		mac != base64.StdEncoding.EncodeToString([]byte{4, 5, 6}) {
		t.Fatalf("server saw %s %s %q %q %q %q", method, path, body, counter, session, mac)
	}
	if len(blobs) != 1 || blobs[0].Version != 2 {
		t.Fatalf("blobs %+v", blobs)
	}
}

func TestSignedRequestsRefuseQueryStrings(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()

	for _, path := range []string{wire.PathAccountBlobs + "?x=1", "no-slash", wire.PathAccountBlobs + "#frag"} {
		_, err := New(srv.URL, srv.Client()).AccountBlobs(context.Background(), service.AuthRequest{Method: "GET", Path: path})
		if err == nil {
			t.Fatalf("path %q was accepted", path)
		}
	}

	if called {
		t.Fatal("a request was sent")
	}
}

func TestBadBlobHashIsAProtocolError(t *testing.T) {
	srv := httptest.NewServer(answer(200, `{"blobs":[{"kind":1,"version":1,"prev_hash":"AQID","data":"AA=="}]}`))
	defer srv.Close()

	_, err := New(srv.URL, srv.Client()).AccountBlobs(context.Background(), service.AuthRequest{
		Method: "GET", Path: wire.PathAccountBlobs,
	})
	if !errors.Is(err, client.ErrProtocol) {
		t.Fatalf("error = %v, want ErrProtocol", err)
	}
}

func TestHugeAnswersAreRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"blobs":"` + strings.Repeat("a", 2<<20) + `"}`))
	}))
	defer srv.Close()

	if _, err := New(srv.URL, srv.Client()).AccountBlobs(context.Background(), service.AuthRequest{
		Method: "GET", Path: wire.PathAccountBlobs,
	}); err == nil {
		t.Fatal("a 2 MiB answer was accepted")
	}
}

func TestRedirectsAreNeverFollowed(t *testing.T) {
	followed := false

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			followed = true
			return
		}
		http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	// A client that would follow redirects by default.
	hc := srv.Client()

	_, err := New(srv.URL, hc).AccountBlobs(context.Background(), service.AuthRequest{
		SessionID: []byte{1}, Counter: 1, Method: "GET", Path: wire.PathAccountBlobs, MAC: []byte{2},
	})
	if err == nil {
		t.Fatal("a redirect was treated as success")
	}
	if followed {
		t.Fatal("the redirect was followed")
	}
}
