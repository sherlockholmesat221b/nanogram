// File: client/session.go

package client

import (
	"sync"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/zkcrypto"
)

// Account holds the secrets a login opens. Wipe them when done.
type Account struct {
	KEK       []byte // account key
	MEK       []byte // key for the user's own stored history
	MLKEMSeed []byte // 64 byte seed of the ML-KEM-768 key pair
	SignSeed  []byte // 32 byte seed of the Ed25519 key pair
}

// Session is a logged in session. Sign makes the signed request headers.
type Session struct {
	UserID   []byte
	ID       []byte
	Scope    string
	Account  *Account
	Warnings []string // things the user should hear about, for example a changed KEK version

	mu         sync.Mutex
	requestKey []byte
	counter    uint64
}

// Sign returns the authenticated request for one call. The counter goes up on
// every call, so a request is never signed twice.
func (s *Session) Sign(method, path string, body []byte) service.AuthRequest {
	s.mu.Lock()
	s.counter++
	counter := s.counter
	key := s.requestKey
	s.mu.Unlock()

	return service.AuthRequest{
		SessionID: s.ID,
		Counter:   counter,
		Method:    method,
		Path:      path,
		Body:      body,
		MAC:       zkcrypto.RequestMAC(key, method, path, counter, body),
	}
}

// Wipe overwrites the session's secrets. The session is useless afterwards.
func (s *Session) Wipe() {
	s.mu.Lock()
	defer s.mu.Unlock()

	clear(s.requestKey)
	s.requestKey = nil

	if s.Account != nil {
		clear(s.Account.KEK)
		clear(s.Account.MEK)
		clear(s.Account.MLKEMSeed)
		clear(s.Account.SignSeed)
	}
}
