// File: internal/e2e/helpers_test.go

package e2e

import (
	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/zkcrypto"
)

// recoverySecret turns the recovery words into the secret the recovery
// credential was registered with.
func recoverySecret(phrase string) ([]byte, error) {
	key, err := zkcrypto.RecoveryKeyFromPhrase(phrase)
	if err != nil {
		return nil, err
	}
	defer clear(key)

	return zkcrypto.RecoveryLoginSecret(key)
}

func recoveryCredentialID(userID []byte) ([]byte, error) {
	return zkcrypto.RecoveryCredentialID(userID)
}

func requestKey(sessionKey []byte) ([]byte, error) {
	return zkcrypto.RequestKey(sessionKey)
}

func signedRequest(key, sessionID []byte, counter uint64, method, path string) service.AuthRequest {
	return service.AuthRequest{
		SessionID: sessionID,
		Counter:   counter,
		Method:    method,
		Path:      path,
		MAC:       zkcrypto.RequestMAC(key, method, path, counter, nil),
	}
}
