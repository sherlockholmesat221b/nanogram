// File: internal/service/types.go

package service

import (
	"io"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/auth"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

// Config configures a Service.
type Config struct {
	Auth  *auth.Server
	Store store.Store
	Now   func() time.Time
	Rand  io.Reader
}

// RegisterStartResult contains the server's registration responses.
type RegisterStartResult struct {
	UserID           []byte
	PasswordResponse []byte
	RecoveryResponse []byte
}

// BlobUpload describes a blob submitted during registration.
type BlobUpload struct {
	Kind     byte
	Version  uint64
	PrevHash [32]byte
	Data     []byte
}

// PublicKeyUpload describes a public key submitted during registration.
type PublicKeyUpload struct {
	Kind string
	Key  []byte
}

// RegisterFinishRequest contains the data required to finish registration.
type RegisterFinishRequest struct {
	UserID         []byte
	Username       string
	PasswordRecord []byte
	RecoveryRecord []byte
	Blobs          []BlobUpload
	PublicKeys     []PublicKeyUpload
}

// BlobInfo describes a stored blob.
type BlobInfo struct {
	Kind     byte
	Version  uint64
	PrevHash [32]byte
	Data     []byte
}

// LoginStartResult contains the server's response to a login start.
type LoginStartResult struct {
	LoginID []byte
	UserID  []byte
	KE2     []byte
}

// SessionInfo describes an authenticated session.
type SessionInfo struct {
	SessionID []byte
	UserID    []byte
	Scope     string
}

// AuthRequest contains the data authenticated by a request MAC.
type AuthRequest struct {
	SessionID []byte
	Counter   uint64
	Method    string
	Path      string
	Body      []byte
	MAC       []byte
}
