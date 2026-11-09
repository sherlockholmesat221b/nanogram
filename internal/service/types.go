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
	Auth      *auth.Server
	Store     store.Store
	Now       func() time.Time
	Rand      io.Reader
	PowSecret []byte // required; used for PoW MACs and username hashing
}

// RegisterStartResult contains the server's registration responses.
type RegisterStartResult struct {
	UserID           []byte
	PasswordResponse []byte
	RecoveryResponse []byte
	ServerPublicKey  []byte
	OnionSignature   []byte
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
	LoginID         []byte
	UserID          []byte
	KE2             []byte
	ServerPublicKey []byte
	OnionSignature  []byte
}

// SessionInfo describes an authenticated session.
type SessionInfo struct {
	SessionID      []byte
	UserID         []byte
	Scope          string
	RecentFailures RecentFailures
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

// BlobHeader is a blob's metadata without its data.
type BlobHeader struct {
	Version  uint64
	PrevHash [32]byte
	Hash     [32]byte
}

// RecoveryViewResult is what a recovery-blob read returns: the recovery blob
// and the current KEK blob's header.
type RecoveryViewResult struct {
	Recovery  BlobInfo
	KEKHeader BlobHeader
}

// RecentFailures is the attempt summary shown to the user after a successful
// login. First and Last are zero when Count is zero.
type RecentFailures struct {
	Count int
	First time.Time
	Last  time.Time
}

// ServerInfoResult is what ServerInfo returns: the server's OPAQUE public
// key and, when the server signs it with its onion key, that signature.
type ServerInfoResult struct {
	PublicKey      []byte
	OnionSignature []byte
}
