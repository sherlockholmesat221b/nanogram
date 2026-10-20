// File: client/errors.go

package client

import "errors"

// Errors returned by the client. Errors from the service (for example a taken
// username) are passed through unchanged.
var (
	// ErrLoginFailed is returned for every kind of failed login: wrong
	// passphrase, unknown user, or a failed proof. It always appears after the
	// slow key stretching has been done, so the timing does not tell them apart.
	ErrLoginFailed = errors.New("login failed")

	// ErrPassphraseMismatch means the passphrase and its confirmation differ.
	ErrPassphraseMismatch = errors.New("the passphrase and its confirmation differ")

	// ErrWeakPassphrase means the passphrase was refused before anything was sent.
	ErrWeakPassphrase = errors.New("passphrase refused")

	// ErrProtocol means the server answered with something that cannot be right.
	ErrProtocol = errors.New("unexpected answer from the server")

	// ErrBadBlobs means the server returned a wrong set of blobs.
	ErrBadBlobs = errors.New("the server returned unexpected blobs")

	// ErrBlobRejected means a blob did not authenticate: it was changed, moved
	// to another user, kind or version, or the keys do not match.
	ErrBlobRejected = errors.New("a blob did not authenticate")

	// ErrRollback means the server returned an older version of a blob than
	// this device has seen before.
	ErrRollback = errors.New("the server returned older data than seen before")

	// ErrTamper means the server returned different data for a version this
	// device has seen before.
	ErrTamper = errors.New("the server returned different data for a known version")

	// ErrHeadsNotSaved means the remembered blob versions could not be saved.
	ErrHeadsNotSaved = errors.New("the remembered blob versions could not be saved")
)
