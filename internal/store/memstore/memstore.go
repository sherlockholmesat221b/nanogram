// File: internal/store/memstore/memstore.go

package memstore

import (
	"context"
	"sync"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

type reservation struct {
	userID  []byte
	expires time.Time
}

type opaqueKey struct {
	userID  string
	kind    string
	pending bool
}

type blobKey struct {
	userID  string
	kind    byte
	version uint64
}

type pubKeyKey struct {
	userID  string
	kind    string
	version uint32
}

type MemStore struct {
	mu           sync.Mutex
	usersByName  map[string]store.User
	usersByID    map[string]store.User
	reservations map[string]reservation
	opaque       map[opaqueKey]store.OpaqueRecord
	blobs        map[blobKey]store.Blob
	pubKeys      map[pubKeyKey]store.PublicKey
	expiries     map[string]time.Time // userID string -> pending expiry time
	loginStates  map[[32]byte]store.LoginState
	sessions     map[[32]byte]store.Session
}

func New() *MemStore {
	return &MemStore{
		usersByName:  make(map[string]store.User),
		usersByID:    make(map[string]store.User),
		reservations: make(map[string]reservation),
		opaque:       make(map[opaqueKey]store.OpaqueRecord),
		blobs:        make(map[blobKey]store.Blob),
		pubKeys:      make(map[pubKeyKey]store.PublicKey),
		expiries:     make(map[string]time.Time),
		loginStates:  make(map[[32]byte]store.LoginState),
		sessions:     make(map[[32]byte]store.Session),
	}
}

var _ store.Store = (*MemStore)(nil)

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func cloneUser(u store.User) store.User {
	u.ID = clone(u.ID)
	return u
}

func cloneOpaque(r store.OpaqueRecord) store.OpaqueRecord {
	r.UserID = clone(r.UserID)
	r.Record = clone(r.Record)
	return r
}

func cloneBlob(b store.Blob) store.Blob {
	b.UserID = clone(b.UserID)
	b.Data = clone(b.Data)
	return b
}

func clonePublicKey(p store.PublicKey) store.PublicKey {
	p.UserID = clone(p.UserID)
	p.Key = clone(p.Key)
	return p
}

func cloneSession(s store.Session) store.Session {
	s.UserID = clone(s.UserID)
	s.Key = clone(s.Key)
	return s
}

func cloneLoginState(s store.LoginState) store.LoginState {
	s.State = clone(s.State)
	return s
}
