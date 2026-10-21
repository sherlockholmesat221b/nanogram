// File: client/httptransport/httptransport.go

// Package httptransport carries the client's requests over the HTTP API.
package httptransport

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/client"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/wire"
)

// maxResponseBytes limits how much of an answer is read.
const maxResponseBytes = 1 << 20

// Transport implements client.Transport over HTTP.
type Transport struct {
	base string
	hc   *http.Client
}

var _ client.Transport = (*Transport)(nil)

// New returns a Transport for the server at baseURL (for example
// "http://127.0.0.1:8080"). hc may be nil. Redirects are never followed,
// whatever hc says, because the signed headers must not be sent anywhere else.
// To reach an onion address, pass an hc whose Transport uses a Tor proxy.
func New(baseURL string, hc *http.Client) *Transport {
	var c http.Client

	if hc == nil {
		c.Timeout = 60 * time.Second
	} else {
		c = *hc
	}

	c.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &Transport{base: strings.TrimRight(baseURL, "/"), hc: &c}
}

// statusError maps an unsuccessful answer to an error. The text the server
// sent is never copied into the error, only a code we know.
func statusError(status int, body []byte, unauthorized error) error {
	var e wire.ErrorResponse
	_ = json.Unmarshal(body, &e)

	switch status {
	case http.StatusUnauthorized:
		return unauthorized

	case http.StatusConflict:
		if e.Error == "username_taken" {
			return service.ErrUsernameTaken
		}

	case http.StatusBadRequest:
		if e.Error == "invalid_username" {
			return service.ErrInvalidUsername
		}
		return service.ErrInvalidRequest

	case http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType:
		return service.ErrInvalidRequest
	}

	return fmt.Errorf("the server answered with status %d", status)
}

// do sends one request and checks the status. When out is not nil the answer
// is decoded into it.
func (t *Transport) do(
	ctx context.Context,
	method, path string,
	headers map[string]string,
	body []byte,
	wantStatus int,
	unauthorized error,
	out any,
) error {
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, t.base+path, reader)
	if err != nil {
		return err
	}

	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := t.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponseBytes {
		return errors.New("the server's answer is too large")
	}

	if resp.StatusCode != wantStatus {
		return statusError(resp.StatusCode, data, unauthorized)
	}

	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("%w: %v", client.ErrProtocol, err)
		}
	}

	return nil
}

func (t *Transport) post(ctx context.Context, path string, in any, wantStatus int, unauthorized error, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}

	return t.do(ctx, http.MethodPost, path, nil, body, wantStatus, unauthorized, out)
}

// RegisterStart implements client.Transport.
func (t *Transport) RegisterStart(ctx context.Context, username string, passwordReq, recoveryReq []byte) (service.RegisterStartResult, error) {
	var res wire.RegisterStartResponse

	err := t.post(ctx, wire.PathRegisterStart, wire.RegisterStartRequest{
		Username:        username,
		PasswordRequest: passwordReq,
		RecoveryRequest: recoveryReq,
	}, http.StatusOK, service.ErrUnauthorized, &res)
	if err != nil {
		return service.RegisterStartResult{}, err
	}

	return service.RegisterStartResult{
		UserID:           res.UserID,
		PasswordResponse: res.PasswordResponse,
		RecoveryResponse: res.RecoveryResponse,
	}, nil
}

// RegisterFinish implements client.Transport.
func (t *Transport) RegisterFinish(ctx context.Context, r service.RegisterFinishRequest) error {
	return t.post(
		ctx, wire.PathRegisterFinish, wire.RegisterFinishFromService(r),
		http.StatusNoContent, service.ErrUnauthorized, nil,
	)
}

// LoginStart implements client.Transport.
func (t *Transport) LoginStart(ctx context.Context, username, kind string, ke1 []byte) (service.LoginStartResult, error) {
	var res wire.LoginStartResponse

	err := t.post(ctx, wire.PathLoginStart, wire.LoginStartRequest{
		Username: username,
		Kind:     kind,
		KE1:      ke1,
	}, http.StatusOK, service.ErrLoginFailed, &res)
	if err != nil {
		return service.LoginStartResult{}, err
	}

	return service.LoginStartResult{LoginID: res.LoginID, UserID: res.UserID, KE2: res.KE2}, nil
}

// LoginFinish implements client.Transport.
func (t *Transport) LoginFinish(ctx context.Context, loginID, ke3 []byte) (service.SessionInfo, error) {
	var res wire.LoginFinishResponse

	err := t.post(ctx, wire.PathLoginFinish, wire.LoginFinishRequest{
		LoginID: loginID,
		KE3:     ke3,
	}, http.StatusOK, service.ErrLoginFailed, &res)
	if err != nil {
		return service.SessionInfo{}, err
	}

	return service.SessionInfo{SessionID: res.SessionID, UserID: res.UserID, Scope: res.Scope}, nil
}

// AccountBlobs implements client.Transport. The request is sent with exactly
// the method, path and body that were signed.
func (t *Transport) AccountBlobs(ctx context.Context, r service.AuthRequest) ([]service.BlobInfo, error) {
	if !strings.HasPrefix(r.Path, "/") || strings.ContainsAny(r.Path, "?#") {
		return nil, errors.New("invalid request path")
	}

	headers := map[string]string{
		wire.HeaderSession: base64.StdEncoding.EncodeToString(r.SessionID),
		wire.HeaderCounter: strconv.FormatUint(r.Counter, 10),
		wire.HeaderMAC:     base64.StdEncoding.EncodeToString(r.MAC),
	}

	var res wire.BlobsResponse
	if err := t.do(ctx, r.Method, r.Path, headers, r.Body, http.StatusOK, service.ErrUnauthorized, &res); err != nil {
		return nil, err
	}

	blobs := make([]service.BlobInfo, 0, len(res.Blobs))
	for _, b := range res.Blobs {
		info, err := b.ToInfo()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", client.ErrProtocol, err)
		}

		blobs = append(blobs, info)
	}

	return blobs, nil
}
