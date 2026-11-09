// File: internal/wire/serverinfo.go

package wire

// PathServerInfo returns the server's OPAQUE public key. It is
// unauthenticated and returns only public data.
const PathServerInfo = "/v1/server-info"

// ServerInfoResponse is the body of a server-info answer.
type ServerInfoResponse struct {
	ServerPublicKey []byte `json:"server_public_key"`
}
