// File: internal/api/api.go

// Package api exposes the service over HTTP. It only translates: it decodes
// requests, calls the service, and maps errors to fixed status codes and
// short error codes. All security decisions are made in the service.
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"mime"
	"net/http"
	"strconv"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/wire"
)

// maxBodyBytes limits every request body.
const maxBodyBytes = 64 << 10

// Service is what the handlers need from the service layer. *service.Service
// satisfies it, and tests can replace it.
type Service interface {
	RegisterStart(ctx context.Context, username string, passwordReq, recoveryReq []byte) (service.RegisterStartResult, error)
	RegisterFinish(ctx context.Context, r service.RegisterFinishRequest) error
	LoginStart(ctx context.Context, username, kind string, ke1 []byte) (service.LoginStartResult, error)
	LoginFinish(ctx context.Context, loginID, ke3 []byte) (service.SessionInfo, error)
	Authenticate(ctx context.Context, r service.AuthRequest, scope string) (store.Session, error)
	CurrentBlobs(ctx context.Context, userID []byte, kinds ...byte) ([]service.BlobInfo, error)
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
	mux.HandleFunc("POST "+wire.PathRegisterStart, h.registerStart)
	mux.HandleFunc("POST "+wire.PathRegisterFinish, h.registerFinish)
	mux.HandleFunc("POST "+wire.PathLoginStart, h.loginStart)
	mux.HandleFunc("POST "+wire.PathLoginFinish, h.loginFinish)
	mux.HandleFunc("GET "+wire.PathAccountBlobs, h.accountBlobs)
	mux.HandleFunc("GET "+wire.PathRecoveryBlob, h.recoveryBlob)

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

	res, err := h.svc.RegisterStart(
		r.Context(),
		req.Username,
		req.PasswordRequest,
		req.RecoveryRequest,
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

	res, err := h.svc.LoginStart(r.Context(), req.Username, req.Kind, req.KE1)
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
	})
}

func (h *handler) accountBlobs(w http.ResponseWriter, r *http.Request) {
	session, ok := h.authenticated(w, r, "full")
	if !ok {
		return
	}

	h.writeBlobs(
		w, r, session.UserID,
		store.BlobKindKEK, store.BlobKindMEK, store.BlobKindIdentity,
	)
}

func (h *handler) recoveryBlob(w http.ResponseWriter, r *http.Request) {
	session, ok := h.authenticated(w, r, "recovery")
	if !ok {
		return
	}

	h.writeBlobs(w, r, session.UserID, store.BlobKindRecovery)
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

// authenticated reads the signature headers and the body, and asks the service
// to check them. The signature covers the method, the path, the counter and the
// body, so a query string would be unprotected: requests with one are refused.
// When it returns false the response has already been written.
func (h *handler) authenticated(
	w http.ResponseWriter,
	r *http.Request,
	scope string,
) (store.Session, bool) {
	var none store.Session

	if r.URL.RawQuery != "" {
		writeError(w, http.StatusBadRequest, "invalid_request")
		return none, false
	}

	sessionID, err := base64.StdEncoding.DecodeString(r.Header.Get(wire.HeaderSession))
	if err != nil || len(sessionID) == 0 {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return none, false
	}

	mac, err := base64.StdEncoding.DecodeString(r.Header.Get(wire.HeaderMAC))
	if err != nil || len(mac) == 0 {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return none, false
	}

	counter, err := strconv.ParseUint(r.Header.Get(wire.HeaderCounter), 10, 64)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return none, false
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeDecodeError(w, err)
		return none, false
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
		return none, false
	}

	return session, true
}
