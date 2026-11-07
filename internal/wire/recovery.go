// File: internal/wire/recovery.go

package wire

import "gitlab.com/sherlockholmesat221b/nanogram/internal/service"

// Paths of the recovery reset and rotation API.
const (
	PathAccountRecoveryBlob   = "/v1/account/recovery/blob"
	PathRecoveryPasswordStart = "/v1/recovery/password/start"
	PathRecoveryPasswordBegin = "/v1/recovery/password/begin"
	PathRecoveryRotateStart   = "/v1/account/recovery/rotate/start"
	PathRecoveryRotateBegin   = "/v1/account/recovery/rotate/begin"
	PathRecoveryDisable       = "/v1/account/recovery/disable"
)

// BlobHeader describes a stored blob without its data. It is returned so a
// recovery session can chain the next KEK blob onto the current one.
type BlobHeader struct {
	Version  uint64 `json:"version"`
	PrevHash []byte `json:"prev_hash"`
	Hash     []byte `json:"hash"`
}

// RecoveryBlobsResponse is what both recovery-blob routes return.
type RecoveryBlobsResponse struct {
	Blobs     []Blob     `json:"blobs"`
	KEKHeader BlobHeader `json:"kek_header"`
}

// RecoveryRotateStartRequest asks for the server's OPAQUE half of a new
// recovery credential.
type RecoveryRotateStartRequest struct {
	RecoveryRequest []byte `json:"recovery_request"`
}

// RecoveryRotateStartResponse carries the server's OPAQUE answer.
type RecoveryRotateStartResponse struct {
	RecoveryResponse []byte `json:"recovery_response"`
}

// RecoveryRotateBeginRequest replaces the recovery record and blob with new
// ones chained to the version the client started from.
type RecoveryRotateBeginRequest struct {
	ExpectedVersion uint64 `json:"expected_version"`
	RecoveryRecord  []byte `json:"recovery_record"`
	RecoveryBlob    Blob   `json:"recovery_blob"`
}

// ToService converts the wire header to the service type. It fails when a
// hash is not exactly 32 bytes.
func (h BlobHeader) ToService() (service.BlobHeader, error) {
	prev, err := toHash(h.PrevHash)
	if err != nil {
		return service.BlobHeader{}, err
	}
	hash, err := toHash(h.Hash)
	if err != nil {
		return service.BlobHeader{}, err
	}
	return service.BlobHeader{
		Version:  h.Version,
		PrevHash: prev,
		Hash:     hash,
	}, nil
}
