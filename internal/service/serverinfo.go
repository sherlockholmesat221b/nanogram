// File: internal/service/serverinfo.go

package service

import "context"

// ServerInfo returns the server's OPAQUE public key and, when the server is
// configured to sign it with its onion key, that signature. It is public
// data; authentication is not required and none is attempted.
func (s *Service) ServerInfo(ctx context.Context) (ServerInfoResult, error) {
	return ServerInfoResult{
		PublicKey:      s.auth.PublicKey(),
		OnionSignature: s.auth.OnionSignature(),
	}, nil
}
