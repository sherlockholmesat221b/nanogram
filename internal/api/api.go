// File: internal/api/api.go

// Package api exposes the service over HTTP. It only translates: it decodes
// requests, calls the service, and maps errors to fixed status codes and
// short error codes. All security decisions are made in the service.
package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"strconv"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/pow"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/wire"
)

// maxBodyBytes limits every request body.
const maxBodyBytes = 64 << 10

// Service is what the handlers need from the service layer. *service.Service
// satisfies it, and tests can replace it.
type Service interface {
	PowChallenge(ctx context.Context, purpose, username string) (pow.Challenge, error)
	RegisterStart(ctx context.Context, username string, passwordReq, recoveryReq []byte, solution *pow.Solution) (service.RegisterStartResult, error)
	RegisterFinish(ctx context.Context, r service.RegisterFinishRequest) error
	LoginStart(ctx context.Context, username, kind string, ke1 []byte, solution *pow.Solution) (service.LoginStartResult, error)
	LoginFinish(ctx context.Context, loginID, ke3 []byte) (service.SessionInfo, error)
	Authenticate(ctx context.Context, r service.AuthRequest, scope string) (store.Session, error)
	CurrentBlobs(ctx context.Context, userID []byte, kinds ...byte) ([]service.BlobInfo, error)
	PasswordChangeStart(ctx context.Context, userID, request []byte) ([]byte, error)
	PasswordChangeBegin(ctx context.Context, userID []byte, expectedVersion uint64, record []byte, kek service.BlobUpload) error
	RecoveryView(ctx context.Context, userID []byte) (service.RecoveryViewResult, error)
	RecoveryPasswordStart(ctx context.Context, userID, passwordReq []byte) ([]byte, error)
	RecoveryPasswordBegin(ctx context.Context, userID []byte, expectedVersion uint64, record []byte, kek service.BlobUpload) error
	RecoveryRotateStart(ctx context.Context, userID, recoveryReq []byte) ([]byte, error)
	RecoveryRotateBegin(ctx context.Context, userID []byte, expectedVersion uint64, record []byte, blob service.BlobUpload) error
	RecoveryDisable(ctx context.Context, userID []byte) error
}

type handler struct {
	svc Service
	log *log.Logger
}

// New returns the HTTP handler for the API. Internal errors are written to
// logger (nil discards them); request bodies and secrets are never logged.
func New(svc Service, logger *log.Logger) http.Handler {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}

	h := &handler{svc: svc, log: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("POST "+wire.PathPowChallenge, h.powChallenge)
	mux.HandleFunc("POST "+wire.PathRegisterStart, h.registerStart)
	mux.HandleFunc("POST "+wire.PathRegisterFinish, h.registerFinish)
	mux.HandleFunc("POST "+wire.PathLoginStart, h.loginStart)
	mux.HandleFunc("POST "+wire.PathLoginFinish, h.loginFinish)
	mux.HandleFunc("GET "+wire.PathAccountBlobs, h.accountBlobs)
	mux.HandleFunc("GET "+wire.PathRecoveryBlob, h.recoveryBlob)
	mux.HandleFunc("POST "+wire.PathPasswordStart, h.passwordStart)
	mux.HandleFunc("POST "+wire.PathPasswordBegin, h.passwordBegin)
	mux.HandleFunc("GET "+wire.PathAccountRecoveryBlob, h.accountRecoveryBlob)
	mux.HandleFunc("POST "+wire.PathRecoveryPasswordStart, h.recoveryPasswordStart)
	mux.HandleFunc("POST "+wire.PathRecoveryPasswordBegin, h.recoveryPasswordBegin)
	mux.HandleFunc("POST "+wire.PathRecoveryRotateStart, h.recoveryRotateStart)
	mux.HandleFunc("POST "+wire.PathRecoveryRotateBegin, h.recoveryRotateBegin)
	mux.HandleFunc("POST "+wire.PathRecoveryDisable, h.recoveryDisable)

	return secureHeaders(mux)
}

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// writeError writes {"error": code}. The code is always one of our own fixed
// strings, so it is written without a JSON encoder.
func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"` + code + `"}`))
}

func writeDecodeError(w http.ResponseWriter, err error) {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		writeError(w, http.StatusRequestEntityTooLarge, "too_large")
		return
	}

	writeError(w, http.StatusBadRequest, "invalid_request")
}

// decodeJSON reads exactly one JSON value into dst. It insists on the JSON
// content type, limits the size, and refuses unknown fields and trailing data.
// When it returns false the response has already been written.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return false
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		writeDecodeError(w, err)
		return false
	}

	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeDecodeError(w, err)
		return false
	}

	return true
}

func (h *handler) powChallenge(w http.ResponseWriter, r *http.Request) {
	var req wire.PowChallengeRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	challenge, err := h.svc.PowChallenge(r.Context(), req.Purpose, req.Username)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.ChallengeToWire(challenge))
}

// fail maps a service error to a status and a fixed code. Failed logins and
// failed authentication share one answer. Anything unexpected is logged here
// and reported as a plain internal error.
func (h *handler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrLoginFailed),
		errors.Is(err, service.ErrUnauthorized):
		writeError(w, http.StatusUnauthorized, "unauthorized")

	case errors.Is(err, service.ErrInvalidUsername):
		writeError(w, http.StatusBadRequest, "invalid_username")

	case errors.Is(err, service.ErrInvalidRequest):
		writeError(w, http.StatusBadRequest, "invalid_request")

	case errors.Is(err, service.ErrUsernameTaken):
		writeError(w, http.StatusConflict, "username_taken")

	case errors.Is(err, service.ErrConflict):
		writeError(w, http.StatusConflict, "conflict")

	case errors.Is(err, service.ErrRecoveryNotSetUp):
		writeError(w, http.StatusNotFound, "recovery_not_set_up")

	case errors.Is(err, service.ErrPowInvalid):
		writeError(w, http.StatusPreconditionRequired, "pow_invalid")

	case errors.Is(err, service.ErrBusy):
		writeError(w, http.StatusTooManyRequests, "busy")

	default:
		h.log.Printf("internal error: %v", err)
		writeError(w, http.StatusInternalServerError, "internal")
	}
}

func (h *handler) registerStart(w http.ResponseWriter, r *http.Request) {
	var req wire.RegisterStartRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	var solution *pow.Solution
	if req.Pow != nil {
		s := wire.SolutionFromWire(*req.Pow)
		solution = &s
	}
	res, err := h.svc.RegisterStart(
		r.Context(),
		req.Username,
		req.PasswordRequest,
		req.RecoveryRequest,
		solution,
	)
	if err != nil {
		h.fail(w, err)
		return
	}

	writeJSON(w, http.StatusOK, wire.RegisterStartResponse{
		UserID:           res.UserID,
		PasswordResponse: res.PasswordResponse,
		RecoveryResponse: res.RecoveryResponse,
	})
}

func (h *handler) registerFinish(w http.ResponseWriter, r *http.Request) {
	var req wire.RegisterFinishRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	finish, err := req.ToService()
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	if err := h.svc.RegisterFinish(r.Context(), finish); err != nil {
		h.fail(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) loginStart(w http.ResponseWriter, r *http.Request) {
	var req wire.LoginStartRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	var solution *pow.Solution
	if req.Pow != nil {
		s := wire.SolutionFromWire(*req.Pow)
		solution = &s
	}
	res, err := h.svc.LoginStart(r.Context(), req.Username, req.Kind, req.KE1, solution)
	if err != nil {
		h.fail(w, err)
		return
	}

	writeJSON(w, http.StatusOK, wire.LoginStartResponse{
		LoginID: res.LoginID,
		UserID:  res.UserID,
		KE2:     res.KE2,
	})
}

func (h *handler) loginFinish(w http.ResponseWriter, r *http.Request) {
	var req wire.LoginFinishRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	info, err := h.svc.LoginFinish(r.Context(), req.LoginID, req.KE3)
	if err != nil {
		h.fail(w, err)
		return
	}

	writeJSON(w, http.StatusOK, wire.LoginFinishResponse{
		SessionID: info.SessionID,
		UserID:    info.UserID,
		Scope:     info.Scope,
		RecentFailures: wire.RecentFailures{
			Count: info.RecentFailures.Count,
			First: info.RecentFailures.First.Unix(),
			Last:  info.RecentFailures.Last.Unix(),
		},
	})
}

func (h *handler) accountBlobs(w http.ResponseWriter, r *http.Request) {
	session, _, ok := h.authenticated(w, r, "full")
	if !ok {
		return
	}

	h.writeBlobs(
		w, r, session.UserID,
		store.BlobKindKEK, store.BlobKindMEK, store.BlobKindIdentity,
	)
}

func (h *handler) recoveryBlob(w http.ResponseWriter, r *http.Request) {
	h.recoveryBlobFor(w, r, "recovery")
}

func (h *handler) accountRecoveryBlob(w http.ResponseWriter, r *http.Request) {
	h.recoveryBlobFor(w, r, "full")
}

func (h *handler) recoveryBlobFor(w http.ResponseWriter, r *http.Request, scope string) {
	session, _, ok := h.authenticated(w, r, scope)
	if !ok {
		return
	}

	view, err := h.svc.RecoveryView(r.Context(), session.UserID)
	if err != nil {
		h.fail(w, err)
		return
	}

	writeJSON(w, http.StatusOK, wire.RecoveryBlobsResponse{
		Blobs: []wire.Blob{wire.BlobFromInfo(view.Recovery)},
		KEKHeader: wire.BlobHeader{
			Version:  view.KEKHeader.Version,
			PrevHash: append([]byte(nil), view.KEKHeader.PrevHash[:]...),
			Hash:     append([]byte(nil), view.KEKHeader.Hash[:]...),
		},
	})
}

func (h *handler) writeBlobs(
	w http.ResponseWriter,
	r *http.Request,
	userID []byte,
	kinds ...byte,
) {
	blobs, err := h.svc.CurrentBlobs(r.Context(), userID, kinds...)
	if err != nil {
		h.fail(w, err)
		return
	}

	out := wire.BlobsResponse{Blobs: make([]wire.Blob, 0, len(blobs))}
	for _, b := range blobs {
		out.Blobs = append(out.Blobs, wire.BlobFromInfo(b))
	}

	writeJSON(w, http.StatusOK, out)
}

func (h *handler) recoveryPasswordStart(w http.ResponseWriter, r *http.Request) {
	session, body, ok := h.authenticated(w, r, "recovery")
	if !ok {
		return
	}

	var req wire.PasswordStartRequest
	if !decodeSigned(w, r, body, &req) {
		return
	}

	response, err := h.svc.RecoveryPasswordStart(r.Context(), session.UserID, req.PasswordRequest)
	if err != nil {
		h.fail(w, err)
		return
	}

	writeJSON(w, http.StatusOK, wire.PasswordStartResponse{PasswordResponse: response})
}

func (h *handler) recoveryPasswordBegin(w http.ResponseWriter, r *http.Request) {
	session, body, ok := h.authenticated(w, r, "recovery")
	if !ok {
		return
	}

	var req wire.PasswordBeginRequest
	if !decodeSigned(w, r, body, &req) {
		return
	}

	kek, err := req.KEK.ToUpload()
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	if err := h.svc.RecoveryPasswordBegin(r.Context(), session.UserID, req.ExpectedVersion, req.Record, kek); err != nil {
		h.fail(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) recoveryRotateStart(w http.ResponseWriter, r *http.Request) {
	session, body, ok := h.authenticated(w, r, "full")
	if !ok {
		return
	}

	var req wire.RecoveryRotateStartRequest
	if !decodeSigned(w, r, body, &req) {
		return
	}

	response, err := h.svc.RecoveryRotateStart(r.Context(), session.UserID, req.RecoveryRequest)
	if err != nil {
		h.fail(w, err)
		return
	}

	writeJSON(w, http.StatusOK, wire.RecoveryRotateStartResponse{RecoveryResponse: response})
}

func (h *handler) recoveryRotateBegin(w http.ResponseWriter, r *http.Request) {
	session, body, ok := h.authenticated(w, r, "full")
	if !ok {
		return
	}

	var req wire.RecoveryRotateBeginRequest
	if !decodeSigned(w, r, body, &req) {
		return
	}

	blob, err := req.RecoveryBlob.ToUpload()
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	if err := h.svc.RecoveryRotateBegin(r.Context(), session.UserID, req.ExpectedVersion, req.RecoveryRecord, blob); err != nil {
		h.fail(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) recoveryDisable(w http.ResponseWriter, r *http.Request) {
	session, _, ok := h.authenticated(w, r, "full")
	if !ok {
		return
	}

	if err := h.svc.RecoveryDisable(r.Context(), session.UserID); err != nil {
		h.fail(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// authenticated reads the signature headers and the body, and asks the service
// to check them. The signature covers the method, the path, the counter and the
// body, so a query string would be unprotected: requests with one are refused.
// When it returns false the response has already been written.
func (h *handler) authenticated(
	w http.ResponseWriter,
	r *http.Request,
	scope string,
) (store.Session, []byte, bool) {
	var none store.Session

	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return none, nil, false
	}

	sessionID, err := base64.StdEncoding.DecodeString(r.Header.Get(wire.HeaderSession))
	if err != nil || len(sessionID) == 0 {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return none, nil, false
	}

	mac, err := base64.StdEncoding.DecodeString(r.Header.Get(wire.HeaderMAC))
	if err != nil || len(mac) == 0 {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return none, nil, false
	}

	counter, err := strconv.ParseUint(r.Header.Get(wire.HeaderCounter), 10, 64)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return none, nil, false
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeDecodeError(w, err)
		return none, nil, false
	}

	session, err := h.svc.Authenticate(r.Context(), service.AuthRequest{
		SessionID: sessionID,
		Counter:   counter,
		Method:    r.Method,
		Path:      r.URL.Path,
		Body:      body,
		MAC:       mac,
	}, scope)
	if err != nil {
		h.fail(w, err)
		return none, nil, false
	}

	return session, body, true
}

// decodeSigned decodes the body of a signed request. authenticated has already
// read the body and checked its signature. The rules are those of decodeJSON.
func decodeSigned(w http.ResponseWriter, r *http.Request, body []byte, dst any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return false
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return false
	}

	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return false
	}

	return true
}

func (h *handler) passwordStart(w http.ResponseWriter, r *http.Request) {
	session, body, ok := h.authenticated(w, r, "full")
	if !ok {
		return
	}

	var req wire.PasswordStartRequest
	if !decodeSigned(w, r, body, &req) {
		return
	}

	response, err := h.svc.PasswordChangeStart(r.Context(), session.UserID, req.PasswordRequest)
	if err != nil {
		h.fail(w, err)
		return
	}

	writeJSON(w, http.StatusOK, wire.PasswordStartResponse{PasswordResponse: response})
}

func (h *handler) passwordBegin(w http.ResponseWriter, r *http.Request) {
	session, body, ok := h.authenticated(w, r, "full")
	if !ok {
		return
	}

	var req wire.PasswordBeginRequest
	if !decodeSigned(w, r, body, &req) {
		return
	}

	kek, err := req.KEK.ToUpload()
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	if err := h.svc.PasswordChangeBegin(r.Context(), session.UserID, req.ExpectedVersion, req.Record, kek); err != nil {
		h.fail(w, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
