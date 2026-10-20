// File: internal/wire/wire.go

// Package wire defines the JSON messages that client and server exchange over
// HTTP. Every binary field is a []byte, which encoding/json writes as standard
// base64. Hashes travel as 32 byte slices and are checked on the way in.
package wire

import (
	"errors"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
)

// Paths of the API. Authenticated requests are signed over exactly these
// paths, so client and server must use the same constants.
const (
	PathRegisterStart  = "/v1/register/start"
	PathRegisterFinish = "/v1/register/finish"
	PathLoginStart     = "/v1/login/start"
	PathLoginFinish    = "/v1/login/finish"
	PathAccountBlobs   = "/v1/account/blobs"
	PathRecoveryBlob   = "/v1/recovery/blob"
)

// Headers that carry the request signature on authenticated requests. The
// session id and the MAC are standard base64, the counter is a decimal number.
const (
	HeaderSession = "X-Session"
	HeaderCounter = "X-Counter"
	HeaderMAC     = "X-MAC"
)

// RegisterStartRequest begins a registration. RecoveryRequest is empty when
// the user skips recovery.
type RegisterStartRequest struct {
	Username        string `json:"username"`
	PasswordRequest []byte `json:"password_request"`
	RecoveryRequest []byte `json:"recovery_request,omitempty"`
}

// RegisterStartResponse carries the server's OPAQUE answers and the user id.
type RegisterStartResponse struct {
	UserID           []byte `json:"user_id"`
	PasswordResponse []byte `json:"password_response"`
	RecoveryResponse []byte `json:"recovery_response,omitempty"`
}

// Blob is an encrypted blob together with the metadata the chain needs.
type Blob struct {
	Kind     byte   `json:"kind"`
	Version  uint64 `json:"version"`
	PrevHash []byte `json:"prev_hash"`
	Data     []byte `json:"data"`
}

// PublicKey is a public key uploaded at registration.
type PublicKey struct {
	Kind string `json:"kind"`
	Key  []byte `json:"key"`
}

// RegisterFinishRequest completes a registration.
type RegisterFinishRequest struct {
	UserID         []byte      `json:"user_id"`
	Username       string      `json:"username"`
	PasswordRecord []byte      `json:"password_record"`
	RecoveryRecord []byte      `json:"recovery_record,omitempty"`
	Blobs          []Blob      `json:"blobs"`
	PublicKeys     []PublicKey `json:"public_keys"`
}

// LoginStartRequest begins a login. Kind is "password" or "recovery".
type LoginStartRequest struct {
	Username string `json:"username"`
	Kind     string `json:"kind"`
	KE1      []byte `json:"ke1"`
}

// LoginStartResponse carries the login id, the user id and the OPAQUE reply.
type LoginStartResponse struct {
	LoginID []byte `json:"login_id"`
	UserID  []byte `json:"user_id"`
	KE2     []byte `json:"ke2"`
}

// LoginFinishRequest completes a login.
type LoginFinishRequest struct {
	LoginID []byte `json:"login_id"`
	KE3     []byte `json:"ke3"`
}

// LoginFinishResponse describes the new session.
type LoginFinishResponse struct {
	SessionID []byte `json:"session_id"`
	UserID    []byte `json:"user_id"`
	Scope     string `json:"scope"`
}

// BlobsResponse lists blobs.
type BlobsResponse struct {
	Blobs []Blob `json:"blobs"`
}

// ErrorResponse is the body of every error. Error is a short fixed code.
type ErrorResponse struct {
	Error string `json:"error"`
}

var errBadHash = errors.New("hash must be 32 bytes")

func toHash(b []byte) ([32]byte, error) {
	var h [32]byte
	if len(b) != len(h) {
		return h, errBadHash
	}

	copy(h[:], b)
	return h, nil
}

// ToUpload converts a wire blob to the service type. It fails when the
// previous hash is not exactly 32 bytes.
func (b Blob) ToUpload() (service.BlobUpload, error) {
	prev, err := toHash(b.PrevHash)
	if err != nil {
		return service.BlobUpload{}, err
	}

	return service.BlobUpload{
		Kind:     b.Kind,
		Version:  b.Version,
		PrevHash: prev,
		Data:     b.Data,
	}, nil
}

// BlobFromInfo converts a stored blob to its wire form.
func BlobFromInfo(b service.BlobInfo) Blob {
	return Blob{
		Kind:     b.Kind,
		Version:  b.Version,
		PrevHash: append([]byte(nil), b.PrevHash[:]...),
		Data:     b.Data,
	}
}

// ToService converts the request to the service type. It fails when a blob
// has a previous hash that is not 32 bytes.
func (r RegisterFinishRequest) ToService() (service.RegisterFinishRequest, error) {
	out := service.RegisterFinishRequest{
		UserID:         r.UserID,
		Username:       r.Username,
		PasswordRecord: r.PasswordRecord,
		RecoveryRecord: r.RecoveryRecord,
	}

	for _, b := range r.Blobs {
		upload, err := b.ToUpload()
		if err != nil {
			return service.RegisterFinishRequest{}, err
		}

		out.Blobs = append(out.Blobs, upload)
	}

	for _, k := range r.PublicKeys {
		out.PublicKeys = append(out.PublicKeys, service.PublicKeyUpload{
			Kind: k.Kind,
			Key:  k.Key,
		})
	}

	return out, nil
}

// RegisterFinishFromService converts the service type to its wire form.
func RegisterFinishFromService(r service.RegisterFinishRequest) RegisterFinishRequest {
	out := RegisterFinishRequest{
		UserID:         r.UserID,
		Username:       r.Username,
		PasswordRecord: r.PasswordRecord,
		RecoveryRecord: r.RecoveryRecord,
	}

	for _, b := range r.Blobs {
		out.Blobs = append(out.Blobs, Blob{
			Kind:     b.Kind,
			Version:  b.Version,
			PrevHash: append([]byte(nil), b.PrevHash[:]...),
			Data:     b.Data,
		})
	}

	for _, k := range r.PublicKeys {
		out.PublicKeys = append(out.PublicKeys, PublicKey{
			Kind: k.Kind,
			Key:  k.Key,
		})
	}

	return out
}
