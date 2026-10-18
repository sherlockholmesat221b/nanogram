package store

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound = errors.New("store: not found")
	ErrTaken    = errors.New("store: name taken")
	ErrConflict = errors.New("store: conflict")
)

// Blob kinds use stable byte identifiers.
const (
	BlobKindKEK byte = iota + 1
	BlobKindMEK
	BlobKindIdentity
	BlobKindRecovery
)

type User struct {
	ID        []byte
	Username  string
	CreatedAt time.Time
}

type OpaqueRecord struct {
	UserID     []byte
	Kind       string
	Pending    bool
	Record     []byte
	KSFVersion int
}

type Blob struct {
	UserID    []byte
	Kind      byte
	Version   uint64
	PrevHash  [32]byte
	Data      []byte
	Pending   bool
	CreatedAt time.Time
}

type Session struct {
	IDHash      [32]byte
	UserID      []byte
	Key         []byte
	LastCounter uint64
	ExpiresAt   time.Time
}

type LoginState struct {
	IDHash    [32]byte
	Username  string
	Kind      string
	State     []byte
	ExpiresAt time.Time
}

type Store interface {
	ReserveUsername(
		ctx context.Context,
		username string,
		userID []byte,
		now, until time.Time,
	) error

	CreateUser(
		ctx context.Context,
		u User,
		records []OpaqueRecord,
		blobs []Blob,
		now time.Time,
	) error

	UserByUsername(
		ctx context.Context,
		username string,
	) (User, error)

	CurrentOpaqueRecord(
		ctx context.Context,
		userID []byte,
		kind string,
	) (OpaqueRecord, error)

	CurrentBlob(
		ctx context.Context,
		userID []byte,
		kind byte,
	) (Blob, error)

	BeginPasswordChange(
		ctx context.Context,
		userID []byte,
		expectedKEKVersion uint64,
		rec OpaqueRecord,
		kek Blob,
	) error

	CommitPasswordChange(
		ctx context.Context,
		userID []byte,
	) error

	AbortPasswordChange(
		ctx context.Context,
		userID []byte,
	) error

	PutLoginState(
		ctx context.Context,
		ls LoginState,
	) error

	TakeLoginState(
		ctx context.Context,
		idHash [32]byte,
		now time.Time,
	) (LoginState, error)

	PutSession(
		ctx context.Context,
		s Session,
	) error

	SessionByIDHash(
		ctx context.Context,
		idHash [32]byte,
		now time.Time,
	) (Session, error)

	AdvanceCounter(
		ctx context.Context,
		idHash [32]byte,
		counter uint64,
	) error

	DeleteSessionsForUser(
		ctx context.Context,
		userID []byte,
	) error

	DeleteExpired(
		ctx context.Context,
		now time.Time,
	) error
}
