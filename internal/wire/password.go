// File: internal/wire/password.go

package wire

import "gitlab.com/sherlockholmesat221b/nanogram/internal/service"

// Paths of the password change API. Like the other authenticated routes, they
// are signed over exactly as they are routed.
const (
	PathPasswordStart = "/v1/account/password/start"
	PathPasswordBegin = "/v1/account/password/begin"
)

// PasswordStartRequest asks the server for its half of the OPAQUE
// registration that will produce a record for the new password.
type PasswordStartRequest struct {
	PasswordRequest []byte `json:"password_request"`
}

// PasswordStartResponse carries the server's OPAQUE answer.
type PasswordStartResponse struct {
	PasswordResponse []byte `json:"password_response"`
}

// PasswordBeginRequest stages a password change: the new OPAQUE record and the
// same KEK, re-wrapped under a key made from the new password. ExpectedVersion
// is the KEK version the client started from.
type PasswordBeginRequest struct {
	ExpectedVersion uint64 `json:"expected_version"`
	Record          []byte `json:"record"`
	KEK             Blob   `json:"kek"`
}

// BlobFromUpload converts a service upload to its wire form. It is the inverse
// of Blob.ToUpload.
func BlobFromUpload(b service.BlobUpload) Blob {
	return Blob{
		Kind:     b.Kind,
		Version:  b.Version,
		PrevHash: append([]byte(nil), b.PrevHash[:]...),
		Data:     b.Data,
	}
}
