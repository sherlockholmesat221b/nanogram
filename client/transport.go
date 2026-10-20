// File: client/transport.go

package client

import (
	"context"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
)

// Transport carries the client's requests to a server. The HTTP transport
// implements it over the API, tests implement it by calling the service
// directly. Errors from the server must be mapped to the service errors
// (for example service.ErrUsernameTaken, service.ErrLoginFailed).
type Transport interface {
	RegisterStart(ctx context.Context, username string, passwordReq, recoveryReq []byte) (service.RegisterStartResult, error)
	RegisterFinish(ctx context.Context, r service.RegisterFinishRequest) error
	LoginStart(ctx context.Context, username, kind string, ke1 []byte) (service.LoginStartResult, error)
	LoginFinish(ctx context.Context, loginID, ke3 []byte) (service.SessionInfo, error)
	AccountBlobs(ctx context.Context, r service.AuthRequest) ([]service.BlobInfo, error)
}
