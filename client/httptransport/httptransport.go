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
	"gitlab.com/sherlockholmesat221b/nanogram/internal/pow"
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
		switch e.Error {
		case "username_taken":
			return service.ErrUsernameTaken
		case "conflict":
			return service.ErrConflict
		}

	case http.StatusBadRequest:
		if e.Error == "invalid_username" {
			return service.ErrInvalidUsername
		}
		return service.ErrInvalidRequest

	case http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType:
		return service.ErrInvalidRequest

	case http.StatusPreconditionRequired:
		return service.ErrPowInvalid

	case http.StatusTooManyRequests:
		return service.ErrBusy
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
func (t *Transport) RegisterStart(ctx context.Context, username string, passwordReq, recoveryReq []byte, solution *pow.Solution) (service.RegisterStartResult, error) {
	var res wire.RegisterStartResponse
	req := wire.RegisterStartRequest{Username: username, PasswordRequest: passwordReq, RecoveryRequest: recoveryReq}
	if solution != nil {
		w := wire.SolutionToWire(*solution)
		req.Pow = &w
	}
	if err := t.post(ctx, wire.PathRegisterStart, req, http.StatusOK, service.ErrUnauthorized, &res); err != nil {
		return service.RegisterStartResult{}, err
	}
	return service.RegisterStartResult{
		UserID:           res.UserID,
		PasswordResponse: res.PasswordResponse,
		RecoveryResponse: res.RecoveryResponse,
		ServerPublicKey:  res.ServerPublicKey,
		OnionSignature:   res.OnionSignature,
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
func (t *Transport) LoginStart(ctx context.Context, username, kind string, ke1 []byte, solution *pow.Solution) (service.LoginStartResult, error) {
	var res wire.LoginStartResponse
	req := wire.LoginStartRequest{Username: username, Kind: kind, KE1: ke1}
	if solution != nil {
		w := wire.SolutionToWire(*solution)
		req.Pow = &w
	}
	if err := t.post(ctx, wire.PathLoginStart, req, http.StatusOK, service.ErrLoginFailed, &res); err != nil {
		return service.LoginStartResult{}, err
	}
	return service.LoginStartResult{
		LoginID:         res.LoginID,
		UserID:          res.UserID,
		KE2:             res.KE2,
		ServerPublicKey: res.ServerPublicKey,
		OnionSignature:  res.OnionSignature,
	}, nil
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

	return service.SessionInfo{
		SessionID: res.SessionID,
		UserID:    res.UserID,
		Scope:     res.Scope,
		RecentFailures: service.RecentFailures{
			Count: res.RecentFailures.Count,
			First: time.Unix(res.RecentFailures.First, 0),
			Last:  time.Unix(res.RecentFailures.Last, 0),
		},
	}, nil
}

// AccountBlobs implements client.Transport. The request is sent with exactly
// the method, path and body that were signed.
func (t *Transport) AccountBlobs(ctx context.Context, r service.AuthRequest) ([]service.BlobInfo, error) {
	if !strings.HasPrefix(r.Path, "/") || strings.ContainsAny(r.Path, "?#") {
		return nil, errors.New("invalid request path")
	}

	headers := signatureHeaders(r)

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

func signatureHeaders(r service.AuthRequest) map[string]string {
	return map[string]string{
		wire.HeaderSession: base64.StdEncoding.EncodeToString(r.SessionID),
		wire.HeaderCounter: strconv.FormatUint(r.Counter, 10),
		wire.HeaderMAC:     base64.StdEncoding.EncodeToString(r.MAC),
	}
}

// signedPost sends a signed POST. The body is made first, handed to sign, and
// sent exactly as it was signed.
func (t *Transport) signedPost(ctx context.Context, sign client.Signer, path string, in any, wantStatus int, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}

	r := sign(http.MethodPost, path, body)

	return t.do(ctx, r.Method, r.Path, signatureHeaders(r), r.Body, wantStatus, service.ErrUnauthorized, out)
}

// PasswordStart implements client.Transport.
func (t *Transport) PasswordStart(ctx context.Context, sign client.Signer, passwordReq []byte) ([]byte, error) {
	var res wire.PasswordStartResponse

	err := t.signedPost(ctx, sign, wire.PathPasswordStart, wire.PasswordStartRequest{PasswordRequest: passwordReq}, http.StatusOK, &res)
	if err != nil {
		return nil, err
	}

	return res.PasswordResponse, nil
}

// PasswordBegin implements client.Transport.
func (t *Transport) PasswordBegin(ctx context.Context, sign client.Signer, expectedVersion uint64, record []byte, kek service.BlobUpload) error {
	return t.signedPost(ctx, sign, wire.PathPasswordBegin, wire.PasswordBeginRequest{
		ExpectedVersion: expectedVersion,
		Record:          record,
		KEK:             wire.BlobFromUpload(kek),
	}, http.StatusNoContent, nil)
}

// RecoveryBlob implements client.Transport. It sends a signed GET to either
// the recovery or the account recovery route, chosen by r.Path.
func (t *Transport) RecoveryBlob(ctx context.Context, r service.AuthRequest) (service.RecoveryViewResult, error) {
	if !strings.HasPrefix(r.Path, "/") || strings.ContainsAny(r.Path, "?#") {
		return service.RecoveryViewResult{}, errors.New("invalid request path")
	}

	headers := signatureHeaders(r)

	var res wire.RecoveryBlobsResponse
	if err := t.do(ctx, r.Method, r.Path, headers, r.Body, http.StatusOK, service.ErrUnauthorized, &res); err != nil {
		return service.RecoveryViewResult{}, err
	}

	if len(res.Blobs) != 1 {
		return service.RecoveryViewResult{}, fmt.Errorf("%w: unexpected blobs", client.ErrProtocol)
	}
	recovery, err := res.Blobs[0].ToInfo()
	if err != nil {
		return service.RecoveryViewResult{}, fmt.Errorf("%w: %v", client.ErrProtocol, err)
	}
	header, err := res.KEKHeader.ToService()
	if err != nil {
		return service.RecoveryViewResult{}, fmt.Errorf("%w: %v", client.ErrProtocol, err)
	}

	return service.RecoveryViewResult{Recovery: recovery, KEKHeader: header}, nil
}

func (t *Transport) RecoveryPasswordStart(ctx context.Context, sign client.Signer, passwordReq []byte) ([]byte, error) {
	var res wire.PasswordStartResponse
	if err := t.signedPost(ctx, sign, wire.PathRecoveryPasswordStart, wire.PasswordStartRequest{PasswordRequest: passwordReq}, http.StatusOK, &res); err != nil {
		return nil, err
	}
	return res.PasswordResponse, nil
}

func (t *Transport) RecoveryPasswordBegin(ctx context.Context, sign client.Signer, expectedVersion uint64, record []byte, kek service.BlobUpload) error {
	return t.signedPost(ctx, sign, wire.PathRecoveryPasswordBegin, wire.PasswordBeginRequest{
		ExpectedVersion: expectedVersion,
		Record:          record,
		KEK:             wire.BlobFromUpload(kek),
	}, http.StatusNoContent, nil)
}

func (t *Transport) RecoveryRotateStart(ctx context.Context, sign client.Signer, recoveryReq []byte) ([]byte, error) {
	var res wire.RecoveryRotateStartResponse
	if err := t.signedPost(ctx, sign, wire.PathRecoveryRotateStart, wire.RecoveryRotateStartRequest{RecoveryRequest: recoveryReq}, http.StatusOK, &res); err != nil {
		return nil, err
	}
	return res.RecoveryResponse, nil
}

func (t *Transport) RecoveryRotateBegin(ctx context.Context, sign client.Signer, expectedVersion uint64, record []byte, blob service.BlobUpload) error {
	return t.signedPost(ctx, sign, wire.PathRecoveryRotateBegin, wire.RecoveryRotateBeginRequest{
		ExpectedVersion: expectedVersion,
		RecoveryRecord:  record,
		RecoveryBlob:    wire.BlobFromUpload(blob),
	}, http.StatusNoContent, nil)
}

func (t *Transport) RecoveryDisable(ctx context.Context, sign client.Signer) error {
	return t.signedPost(ctx, sign, wire.PathRecoveryDisable, struct{}{}, http.StatusNoContent, nil)
}

func (t *Transport) PowChallenge(ctx context.Context, purpose, username string) (pow.Challenge, error) {
	var res wire.PowChallengeResponse
	if err := t.post(ctx, wire.PathPowChallenge, wire.PowChallengeRequest{Purpose: purpose, Username: username}, http.StatusOK, service.ErrUnauthorized, &res); err != nil {
		return pow.Challenge{}, err
	}
	return wire.ChallengeFromWire(res), nil
}

// ServerInfo implements client.Transport. It fetches the server's OPAQUE
// public key without authentication.
func (t *Transport) ServerInfo(ctx context.Context) (service.ServerInfoResult, error) {
	var res wire.ServerInfoResponse
	if err := t.do(ctx, http.MethodGet, wire.PathServerInfo, nil, nil, http.StatusOK, service.ErrUnauthorized, &res); err != nil {
		return service.ServerInfoResult{}, err
	}
	return service.ServerInfoResult{
		PublicKey:      res.ServerPublicKey,
		OnionSignature: res.OnionSignature,
	}, nil
}

// ServerURL returns the base URL the transport was created with.
func (t *Transport) ServerURL() string { return t.base }
