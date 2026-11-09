// File: client/onion.go

package client

import (
	"crypto/ed25519"
	"net/url"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/tor"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/zkcrypto"
)

// CheckOnion verifies that the server's onion service key has signed its
// OPAQUE public key. When serverURL is not a .onion address, it returns
// ("", nil) and does nothing.
//
// On a .onion server:
//   - signature present and valid: returns ("", nil);
//   - signature absent: returns a warning and nil. The operator has not
//     configured -onion-key; the client falls back to fingerprint pinning;
//   - signature present but invalid, or the address is malformed: returns
//     ("", ErrServerKeyChanged) and the caller must abort before any secret
//     leaves the client.
func CheckOnion(serverURL string, publicKey, signature []byte) (string, error) {
	u, err := url.Parse(serverURL)
	if err != nil {
		return "", ErrServerKeyChanged
	}
	host := u.Hostname()
	if !tor.IsOnionAddress(host) {
		return "", nil
	}

	onionPub, err := tor.ParseOnionAddress(host)
	if err != nil {
		return "", ErrServerKeyChanged
	}

	if len(signature) == 0 {
		return "onion: server does not sign its public key; using fingerprint pinning only", nil
	}

	msg := append([]byte(zkcrypto.LabelOnion), publicKey...)
	if !ed25519.Verify(onionPub, msg, signature) {
		return "", ErrServerKeyChanged
	}
	return "", nil
}
