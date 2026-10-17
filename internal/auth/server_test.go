package auth

import (
	"bytes"
	"testing"

	"github.com/bytemare/opaque"
)

var (
	serverTestPassword = []byte("correct horse battery staple")
	serverTestUserID   = []byte("user-id-00000001")
	serverTestUsername = "alice"
)

func registerStoredUser(
	t *testing.T,
	conf *opaque.Configuration,
	keys ServerKeys,
	userID, password []byte,
) *StoredUser {
	t.Helper()

	client, err := conf.Client()
	if err != nil {
		t.Fatalf("create registration client: %v", err)
	}

	server := NewServer(keys)
	request := client.RegistrationInit(password)

	responseBytes, err := server.RegistrationResponse(request.Serialize(), userID)
	if err != nil {
		t.Fatalf("registration response: %v", err)
	}

	response, err := client.Deserialize.RegistrationResponse(responseBytes)
	if err != nil {
		t.Fatalf("deserialize registration response: %v", err)
	}

	record, _ := client.RegistrationFinalize(
		response,
		opaque.ClientRegistrationFinalizeOptions{
			ClientIdentity: userID,
			ServerIdentity: nil,
		},
	)

	normalized, err := server.NormalizeRecord(record.Serialize())
	if err != nil {
		t.Fatalf("normalize registration record: %v", err)
	}

	return &StoredUser{
		ID:     append([]byte(nil), userID...),
		Record: normalized,
	}
}

func startClientLogin(
	t *testing.T,
	conf *opaque.Configuration,
	server *Server,
	username string,
	user *StoredUser,
	password []byte,
) (*opaque.Client, []byte, []byte) {
	t.Helper()

	client, err := conf.Client()
	if err != nil {
		t.Fatalf("create login client: %v", err)
	}

	request := client.LoginInit(password)

	ke2, state, err := server.LoginStart(request.Serialize(), username, user)
	if err != nil {
		t.Fatalf("server LoginStart: %v", err)
	}

	return client, ke2, state
}

func finishClientLogin(
	t *testing.T,
	client *opaque.Client,
	userID, ke2 []byte,
) ([]byte, error) {
	t.Helper()

	response, err := client.Deserialize.KE2(ke2)
	if err != nil {
		t.Fatalf("deserialize KE2: %v", err)
	}

	ke3, _, err := client.LoginFinish(
		response,
		opaque.ClientLoginFinishOptions{
			ClientIdentity: userID,
			ServerIdentity: nil,
		},
	)
	if err != nil {
		return nil, err
	}

	return ke3.Serialize(), nil
}

func makeTestKE1(t *testing.T, conf *opaque.Configuration) []byte {
	t.Helper()

	client, err := conf.Client()
	if err != nil {
		t.Fatalf("create KE1 client: %v", err)
	}

	return client.LoginInit(serverTestPassword).Serialize()
}

func assertSameOPRFEvaluation(t *testing.T, first, second []byte) {
	t.Helper()

	const evaluatedElementSize = 32

	if len(first) < evaluatedElementSize || len(second) < evaluatedElementSize {
		t.Fatalf(
			"KE2 too short to contain the evaluated element: first=%d second=%d",
			len(first), len(second),
		)
	}

	if !bytes.Equal(first[:evaluatedElementSize], second[:evaluatedElementSize]) {
		t.Fatal("OPRF evaluated elements differ for repeated equivalent requests")
	}
}

func TestServerRegistrationAndLogin(t *testing.T) {
	conf := NewConfiguration()
	keys := GenerateServerKeys(conf)
	user := registerStoredUser(
		t, conf, keys, serverTestUserID, serverTestPassword,
	)

	client, ke2, state := startClientLogin(
		t, conf, NewServer(keys), serverTestUsername,
		user, serverTestPassword,
	)

	if len(state) == 0 {
		t.Fatal("LoginStart returned an empty state")
	}

	ke3, err := finishClientLogin(t, client, user.ID, ke2)
	if err != nil {
		t.Fatalf("client LoginFinish: %v", err)
	}

	// Restore the serialized state using a different application Server value.
	serverSessionKey, err := NewServer(keys).LoginFinish(state, ke3)
	if err != nil {
		t.Fatalf("server LoginFinish: %v", err)
	}

	if !bytes.Equal(client.SessionKey(), serverSessionKey) {
		t.Fatal("client and server session keys differ")
	}
}

func TestServerWrongPassphrase(t *testing.T) {
	conf := NewConfiguration()
	keys := GenerateServerKeys(conf)
	user := registerStoredUser(
		t, conf, keys, serverTestUserID, serverTestPassword,
	)

	client, ke2, _ := startClientLogin(
		t, conf, NewServer(keys), serverTestUsername,
		user, []byte("incorrect passphrase"),
	)

	_, err := finishClientLogin(t, client, user.ID, ke2)
	if err == nil {
		t.Fatal("client LoginFinish accepted an incorrect passphrase")
	}
}

func TestServerUnknownUsername(t *testing.T) {
	conf := NewConfiguration()
	keys := GenerateServerKeys(conf)
	user := registerStoredUser(
		t, conf, keys, serverTestUserID, serverTestPassword,
	)

	_, realKE2, _ := startClientLogin(
		t, conf, NewServer(keys), serverTestUsername,
		user, serverTestPassword,
	)

	unknownClient, unknownKE2, _ := startClientLogin(
		t, conf, NewServer(keys), "unknown-user",
		nil, serverTestPassword,
	)

	if len(unknownKE2) != len(realKE2) {
		t.Fatalf(
			"KE2 lengths differ: real=%d unknown=%d",
			len(realKE2), len(unknownKE2),
		)
	}

	_, err := finishClientLogin(t, unknownClient, []byte("unknown-user"), unknownKE2)
	if err == nil {
		t.Fatal("client LoginFinish accepted the fake record")
	}
}

func TestNormalizeRecordRejectsTruncatedBytes(t *testing.T) {
	server := NewServer(GenerateServerKeys(NewConfiguration()))

	if _, err := server.NormalizeRecord([]byte{0x01, 0x02}); err == nil {
		t.Fatal("NormalizeRecord accepted a truncated registration record")
	}
}

func TestRegistrationResponseRejects15ByteUserID(t *testing.T) {
	conf := NewConfiguration()
	keys := GenerateServerKeys(conf)
	client, err := conf.Client()
	if err != nil {
		t.Fatalf("create registration client: %v", err)
	}

	request := client.RegistrationInit(serverTestPassword)
	server := NewServer(keys)

	if _, err := server.RegistrationResponse(request.Serialize(), make([]byte, 15)); err == nil {
		t.Fatal("RegistrationResponse accepted a 15-byte user ID")
	}
}

func TestUnknownUsernameOPRFEvaluationIsDeterministic(t *testing.T) {
	conf := NewConfiguration()
	keys := GenerateServerKeys(conf)
	server := NewServer(keys)
	ke1 := makeTestKE1(t, conf)

	first, _, err := server.LoginStart(ke1, "unknown-user", nil)
	if err != nil {
		t.Fatalf("first LoginStart: %v", err)
	}

	second, _, err := server.LoginStart(ke1, "unknown-user", nil)
	if err != nil {
		t.Fatalf("second LoginStart: %v", err)
	}

	assertSameOPRFEvaluation(t, first, second)
}

func TestRealUserOPRFEvaluationIsDeterministic(t *testing.T) {
	conf := NewConfiguration()
	keys := GenerateServerKeys(conf)
	user := registerStoredUser(
		t, conf, keys, serverTestUserID, serverTestPassword,
	)
	server := NewServer(keys)
	ke1 := makeTestKE1(t, conf)

	first, _, err := server.LoginStart(ke1, serverTestUsername, user)
	if err != nil {
		t.Fatalf("first LoginStart: %v", err)
	}

	second, _, err := server.LoginStart(ke1, serverTestUsername, user)
	if err != nil {
		t.Fatalf("second LoginStart: %v", err)
	}

	assertSameOPRFEvaluation(t, first, second)
}

func TestDifferentUnknownUsernamesHaveDifferentOPRFEvaluations(t *testing.T) {
	conf := NewConfiguration()
	keys := GenerateServerKeys(conf)
	server := NewServer(keys)
	ke1 := makeTestKE1(t, conf)

	first, _, err := server.LoginStart(ke1, "unknown-user-a", nil)
	if err != nil {
		t.Fatalf("first LoginStart: %v", err)
	}

	second, _, err := server.LoginStart(ke1, "unknown-user-b", nil)
	if err != nil {
		t.Fatalf("second LoginStart: %v", err)
	}

	const evaluatedElementSize = 32

	if len(first) < evaluatedElementSize || len(second) < evaluatedElementSize {
		t.Fatalf(
			"KE2 too short to contain the evaluated element: first=%d second=%d",
			len(first), len(second),
		)
	}

	if bytes.Equal(first[:evaluatedElementSize], second[:evaluatedElementSize]) {
		t.Fatal("different unknown usernames produced the same OPRF evaluated element")
	}
}
