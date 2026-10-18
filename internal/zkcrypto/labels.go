// File: internal/zkcrypto/labels.go

package zkcrypto

// These strings are part of key derivation and must never change once real users exist.
const (
	LabelWrap          = "zkc/v1/wrap"
	LabelRecovery      = "zkc/v1/recovery"
	LabelRequest       = "zkc/v1/request"
	LabelOpaqueContext = "zkc/v1/opaque"
	LabelFakeUser      = "zkc/v1/fake-user"
	LabelBlob          = "zkc/v1/blob"
	LabelRecoveryLogin = "zkc/v1/recovery-login"
	LabelRecoveryCred  = "zkc/v1/recovery-cred"
)
