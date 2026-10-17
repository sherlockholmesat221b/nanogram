package auth

import (
	"bytes"
	"testing"

	"github.com/bytemare/opaque"
)

var (
	testClientID = []byte("username")
	testServerID = []byte("server")
	testPassword = []byte("correct horse battery staple")
)

type testServerKeys struct {
	privateKey []byte
	publicKey  []byte
	oprfSeed   []byte
}

func newTestServer(t *testing.T, conf *opaque.Configuration, keys testServerKeys) *opaque.Server {
	t.Helper()

	server, err := conf.Server()
	if err != nil {
		t.Fatalf("create server: %v", err)
	}

	if err := server.SetKeyMaterial(testServerID, keys.privateKey, keys.publicKey, keys.oprfSeed); err != nil {
		t.Fatalf("set server key material: %v", err)
	}

	return server
}

func newTestServerKeys(conf *opaque.Configuration) testServerKeys {
	privateKey, publicKey := conf.KeyGen()

	return testServerKeys{
		privateKey: privateKey,
		publicKey:  publicKey,
		oprfSeed:   conf.GenerateOPRFSeed(),
	}
}

func registerTestUser(t *testing.T, conf *opaque.Configuration, password []byte, keys testServerKeys) (*opaque.ClientRecord, []byte) {
	t.Helper()

	client, err := conf.Client()
	if err != nil {
		t.Fatalf("create registration client: %v", err)
	}

	server := newTestServer(t, conf, keys)
	credentialID := opaque.RandomBytes(16)

	request := client.RegistrationInit(password)
	serverRequest, err := server.Deserialize.RegistrationRequest(request.Serialize())
	if err != nil {
		t.Fatalf("deserialize registration request: %v", err)
	}

	serverPublicKey, err := server.Deserialize.DecodeAkePublicKey(keys.publicKey)
	if err != nil {
		t.Fatalf("decode server public key: %v", err)
	}

	response := server.RegistrationResponse(
		serverRequest,
		serverPublicKey,
		credentialID,
		keys.oprfSeed,
	)

	clientResponse, err := client.Deserialize.RegistrationResponse(response.Serialize())
	if err != nil {
		t.Fatalf("deserialize registration response: %v", err)
	}

	registrationRecord, registrationExportKey := client.RegistrationFinalize(
		clientResponse,
		opaque.ClientRegistrationFinalizeOptions{
			ClientIdentity: testClientID,
			ServerIdentity: testServerID,
		},
	)

	serverRecord, err := server.Deserialize.RegistrationRecord(registrationRecord.Serialize())
	if err != nil {
		t.Fatalf("deserialize registration record: %v", err)
	}

	return &opaque.ClientRecord{
		CredentialIdentifier: credentialID,
		ClientIdentity:       testClientID,
		RegistrationRecord:   serverRecord,
	}, registrationExportKey
}

func loginTestUser(t *testing.T, conf *opaque.Configuration, record *opaque.ClientRecord, password []byte, keys testServerKeys) ([]byte, []byte, []byte, error) {
	t.Helper()

	client, err := conf.Client()
	if err != nil {
		t.Fatalf("create login client: %v", err)
	}

	server := newTestServer(t, conf, keys)

	request := client.LoginInit(password)
	serverRequest, err := server.Deserialize.KE1(request.Serialize())
	if err != nil {
		t.Fatalf("deserialize KE1: %v", err)
	}

	response, err := server.LoginInit(serverRequest, record)
	if err != nil {
		t.Fatalf("server LoginInit: %v", err)
	}

	clientResponse, err := client.Deserialize.KE2(response.Serialize())
	if err != nil {
		t.Fatalf("deserialize KE2: %v", err)
	}

	message, exportKey, err := client.LoginFinish(
		clientResponse,
		opaque.ClientLoginFinishOptions{
			ClientIdentity: testClientID,
			ServerIdentity: testServerID,
		},
	)
	if err != nil {
		return nil, nil, nil, err
	}

	if err := server.LoginFinish(message); err != nil {
		t.Fatalf("server LoginFinish: %v", err)
	}

	return client.SessionKey(), server.SessionKey(), exportKey, nil
}

func TestOpaqueRoundTrip(t *testing.T) {
	conf := NewConfiguration()
	keys := newTestServerKeys(conf)
	record, registrationExportKey := registerTestUser(t, conf, testPassword, keys)

	clientSessionKey, serverSessionKey, loginExportKey, err := loginTestUser(
		t, conf, record, testPassword, keys,
	)
	if err != nil {
		t.Fatalf("login with correct password: %v", err)
	}

	if !bytes.Equal(clientSessionKey, serverSessionKey) {
		t.Fatal("client and server session keys differ")
	}

	if !bytes.Equal(registrationExportKey, loginExportKey) {
		t.Fatal("registration and login export keys differ")
	}
}

func TestOpaqueContextBinding(t *testing.T) {
	registrationConf := NewConfiguration()
	keys := newTestServerKeys(registrationConf)
	record, _ := registerTestUser(t, registrationConf, testPassword, keys)

	// The client retains the configured context; the server uses the default.
	clientConf := NewConfiguration()
	serverConf := opaque.DefaultConfiguration()

	client, err := clientConf.Client()
	if err != nil {
		t.Fatalf("create login client: %v", err)
	}

	server := newTestServer(t, serverConf, keys)
	request := client.LoginInit(testPassword)
	serverRequest, err := server.Deserialize.KE1(request.Serialize())
	if err != nil {
		t.Fatalf("deserialize KE1: %v", err)
	}

	response, err := server.LoginInit(serverRequest, record)
	if err != nil {
		t.Fatalf("server LoginInit: %v", err)
	}

	clientResponse, err := client.Deserialize.KE2(response.Serialize())
	if err != nil {
		t.Fatalf("deserialize KE2: %v", err)
	}

	_, _, err = client.LoginFinish(
		clientResponse,
		opaque.ClientLoginFinishOptions{
			ClientIdentity: testClientID,
			ServerIdentity: testServerID,
		},
	)
	if err == nil {
		t.Fatal("LoginFinish succeeded with mismatched OPAQUE contexts")
	}
}

func TestOpaqueWrongPassword(t *testing.T) {
	conf := NewConfiguration()
	keys := newTestServerKeys(conf)
	record, _ := registerTestUser(t, conf, testPassword, keys)

	_, _, _, err := loginTestUser(
		t, conf, record, []byte("incorrect password"), keys,
	)
	if err == nil {
		t.Fatal("expected LoginFinish to reject the wrong password")
	}
}

func TestOpaqueUnknownUserFakeResponse(t *testing.T) {
	conf := NewConfiguration()
	keys := newTestServerKeys(conf)
	record, _ := registerTestUser(t, conf, testPassword, keys)

	realClient, err := conf.Client()
	if err != nil {
		t.Fatalf("create real-user client: %v", err)
	}
	realServer := newTestServer(t, conf, keys)

	realRequest := realClient.LoginInit(testPassword)
	realServerRequest, err := realServer.Deserialize.KE1(realRequest.Serialize())
	if err != nil {
		t.Fatalf("deserialize real-user KE1: %v", err)
	}

	realResponse, err := realServer.LoginInit(realServerRequest, record)
	if err != nil {
		t.Fatalf("real-user LoginInit: %v", err)
	}
	realKE2 := realResponse.Serialize()

	unknownCredentialID := opaque.RandomBytes(16)
	fakeRecord, err := conf.GetFakeRecord(unknownCredentialID)
	if err != nil {
		t.Fatalf("create fake record: %v", err)
	}

	unknownClient, err := conf.Client()
	if err != nil {
		t.Fatalf("create unknown-user client: %v", err)
	}
	unknownServer := newTestServer(t, conf, keys)

	unknownRequest := unknownClient.LoginInit(testPassword)
	unknownServerRequest, err := unknownServer.Deserialize.KE1(unknownRequest.Serialize())
	if err != nil {
		t.Fatalf("deserialize unknown-user KE1: %v", err)
	}

	unknownResponse, err := unknownServer.LoginInit(unknownServerRequest, fakeRecord)
	if err != nil {
		t.Fatalf("fake-record LoginInit: %v", err)
	}
	unknownKE2 := unknownResponse.Serialize()

	t.Logf("real-user serialized KE2 length: %d", len(realKE2))
	t.Logf("unknown-user serialized KE2 length: %d", len(unknownKE2))

	if len(realKE2) != len(unknownKE2) {
		t.Fatalf("serialized KE2 lengths differ: real=%d unknown=%d", len(realKE2), len(unknownKE2))
	}

	clientKE2, err := unknownClient.Deserialize.KE2(unknownKE2)
	if err != nil {
		t.Fatalf("deserialize fake KE2: %v", err)
	}

	_, _, err = unknownClient.LoginFinish(
		clientKE2,
		opaque.ClientLoginFinishOptions{
			ClientIdentity: testClientID,
			ServerIdentity: testServerID,
		},
	)
	if err == nil {
		t.Fatal("expected LoginFinish to reject the fake record")
	}
}

func TestOpaqueMismatchedServerKeys(t *testing.T) {
	for _, mismatch := range []string{"secret key", "OPRF seed"} {
		t.Run(mismatch, func(t *testing.T) {
			conf := NewConfiguration()
			registrationKeys := newTestServerKeys(conf)
			record, _ := registerTestUser(t, conf, testPassword, registrationKeys)

			loginKeys := registrationKeys
			switch mismatch {
			case "secret key":
				loginKeys.privateKey, loginKeys.publicKey = conf.KeyGen()
			case "OPRF seed":
				loginKeys.oprfSeed = conf.GenerateOPRFSeed()
			}

			_, _, _, err := loginTestUser(
				t, conf, record, testPassword, loginKeys,
			)
			if err == nil {
				t.Fatalf("expected LoginFinish to reject mismatched server %s", mismatch)
			}
		})
	}
}
