package auth

import (
	"github.com/bytemare/opaque"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/zkcrypto"
)

// NewConfiguration returns the application's OPAQUE configuration.
// The configuration must be identical on every client and the server,
// so it exists only here.
func NewConfiguration() *opaque.Configuration {
	config := opaque.DefaultConfiguration()
	config.Context = []byte(zkcrypto.LabelOpaqueContext)

	return config
}
