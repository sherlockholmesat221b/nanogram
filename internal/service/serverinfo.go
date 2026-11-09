// File: internal/service/serverinfo.go

package service

import "context"

// ServerInfo returns the server's OPAQUE public key. It is public data;
// authentication is not required and none is attempted.
func (s *Service) ServerInfo(ctx context.Context) ([]byte, error) {
	return s.auth.PublicKey(), nil
}
