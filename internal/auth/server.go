package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/bytemare/opaque"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/zkcrypto"
)

// StoredUser contains a stable user identifier and its serialized OPAQUE registration record.
type StoredUser struct {
	ID     []byte
	Record []byte
}

// Server handles OPAQUE registration and login using the configured context and server keys.
type Server struct {
	conf *opaque.Configuration
	keys ServerKeys
}

// NewServer creates a server using NewConfiguration and the supplied server keys.
func NewServer(keys ServerKeys) *Server {
	return &Server{
		conf: NewConfiguration(),
		keys: keys,
	}
}

// RegistrationResponse rejects user IDs that are not 16 bytes and returns a serialized registration response.
func (s *Server) RegistrationResponse(request, userID []byte) ([]byte, error) {
	if len(userID) != 16 {
		return nil, errors.New("user ID must be 16 bytes")
	}

	server, err := s.conf.Server()
	if err != nil {
		return nil, fmt.Errorf("create OPAQUE server: %w", err)
	}

	registrationRequest, err := server.Deserialize.RegistrationRequest(request)
	if err != nil {
		return nil, fmt.Errorf("deserialize registration request: %w", err)
	}

	publicKey, err := server.Deserialize.DecodeAkePublicKey(s.keys.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode server public key: %w", err)
	}

	response := server.RegistrationResponse(
		registrationRequest,
		publicKey,
		userID,
		s.keys.OPRFSeed,
	)

	return response.Serialize(), nil
}

// NormalizeRecord validates a serialized registration record and returns its normalized serialization.
func (s *Server) NormalizeRecord(record []byte) ([]byte, error) {
	deserializer, err := s.conf.Deserializer()
	if err != nil {
		return nil, fmt.Errorf("create OPAQUE deserializer: %w", err)
	}

	decoded, err := deserializer.RegistrationRecord(record)
	if err != nil {
		return nil, fmt.Errorf("deserialize registration record: %w", err)
	}

	return decoded.Serialize(), nil
}

// LoginStart returns a serialized KE2 response and serialized server state for a login request.
func (s *Server) LoginStart(
	ke1 []byte,
	username string,
	user *StoredUser,
) (ke2, state []byte, err error) {
	server, err := s.conf.Server()
	if err != nil {
		return nil, nil, fmt.Errorf("create OPAQUE server: %w", err)
	}

	if err := server.SetKeyMaterial(
		nil,
		s.keys.PrivateKey,
		s.keys.PublicKey,
		s.keys.OPRFSeed,
	); err != nil {
		return nil, nil, fmt.Errorf("set server key material: %w", err)
	}

	request, err := server.Deserialize.KE1(ke1)
	if err != nil {
		return nil, nil, fmt.Errorf("deserialize KE1: %w", err)
	}

	var record *opaque.ClientRecord

	if user != nil {
		registrationRecord, err := server.Deserialize.RegistrationRecord(user.Record)
		if err != nil {
			return nil, nil, fmt.Errorf("deserialize registration record: %w", err)
		}

		record = &opaque.ClientRecord{
			CredentialIdentifier: user.ID,
			ClientIdentity:       user.ID,
			RegistrationRecord:   registrationRecord,
		}
	} else {
		// A deterministic fake ID keeps the OPRF response consistent for repeated
		// requests for the same unknown username.
		mac := hmac.New(sha256.New, s.keys.OPRFSeed)
		_, _ = mac.Write([]byte(zkcrypto.LabelFakeUser + username))
		fakeID := mac.Sum(nil)[:16]

		record, err = s.conf.GetFakeRecord(fakeID)
		if err != nil {
			return nil, nil, fmt.Errorf("create fake client record: %w", err)
		}
	}

	response, err := server.LoginInit(request, record)
	if err != nil {
		return nil, nil, fmt.Errorf("initialize login: %w", err)
	}

	return response.Serialize(), server.SerializeState(), nil
}

// LoginFinish restores serialized login state and returns a session key only after client authentication succeeds.
func (s *Server) LoginFinish(state, ke3 []byte) ([]byte, error) {
	server, err := s.conf.Server()
	if err != nil {
		return nil, fmt.Errorf("create OPAQUE server: %w", err)
	}

	if err := server.SetKeyMaterial(
		nil,
		s.keys.PrivateKey,
		s.keys.PublicKey,
		s.keys.OPRFSeed,
	); err != nil {
		return nil, fmt.Errorf("set server key material: %w", err)
	}

	if err := server.SetAKEState(state); err != nil {
		return nil, fmt.Errorf("restore server state: %w", err)
	}

	message, err := server.Deserialize.KE3(ke3)
	if err != nil {
		return nil, fmt.Errorf("deserialize KE3: %w", err)
	}

	if err := server.LoginFinish(message); err != nil {
		return nil, errors.New("login authentication failed")
	}

	return server.SessionKey(), nil
}
