package service

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bytemare/opaque"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/auth"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/store/memstore"
)

const (
	testUsername = "alice"
	testPassword = "correct horse battery staple"
	testRecovery = "recovery credential"
)

type registrationFixture struct {
	service *Service
	store   *memstore.MemStore
	conf    *opaque.Configuration
	now     time.Time
}

func newRegistrationFixture(t *testing.T) *registrationFixture {
	t.Helper()

	conf := auth.NewConfiguration()
	keys := auth.GenerateServerKeys(conf)
	m := memstore.New()
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)

	f := &registrationFixture{
		store: m,
		conf:  conf,
		now:   now,
	}

	f.service = New(Config{
		Auth:  auth.NewServer(keys),
		Store: m,
		Now: func() time.Time {
			return f.now
		},
	})

	return f
}

func (f *registrationFixture) client(t *testing.T) *opaque.Client {
	t.Helper()

	client, err := f.conf.Client()
	if err != nil {
		t.Fatalf("create OPAQUE client: %v", err)
	}

	return client
}

func registrationRecord(
	t *testing.T,
	client *opaque.Client,
	responseBytes []byte,
	clientID []byte,
) []byte {
	t.Helper()

	response, err := client.Deserialize.RegistrationResponse(responseBytes)
	if err != nil {
		t.Fatalf("deserialize registration response: %v", err)
	}

	record, _ := client.RegistrationFinalize(
		response,
		opaque.ClientRegistrationFinalizeOptions{
			ClientIdentity: clientID,
			ServerIdentity: []byte("server"),
		},
	)

	return record.Serialize()
}

func validBlobs() []BlobUpload {
	return []BlobUpload{
		{
			Kind:    store.BlobKindKEK,
			Version: 1,
			Data:    bytes.Repeat([]byte{1}, 41),
		},
		{
			Kind:    store.BlobKindMEK,
			Version: 1,
			Data:    bytes.Repeat([]byte{2}, 41),
		},
		{
			Kind:    store.BlobKindIdentity,
			Version: 1,
			Data:    bytes.Repeat([]byte{3}, 41),
		},
	}
}

func validPublicKeys() []PublicKeyUpload {
	return []PublicKeyUpload{
		{
			Kind: "mlkem",
			Key:  []byte{1, 2, 3},
		},
		{
			Kind: "sign",
			Key:  []byte{4, 5, 6},
		},
	}
}

func (f *registrationFixture) validFinishRequest(
	t *testing.T,
	username string,
	withRecovery bool,
) (RegisterFinishRequest, RegisterStartResult) {
	t.Helper()

	passwordClient := f.client(t)
	passwordRequest := passwordClient.RegistrationInit([]byte(testPassword))

	var recoveryClient *opaque.Client
	var recoveryRequest []byte

	if withRecovery {
		recoveryClient = f.client(t)
		recoveryRequest = recoveryClient.RegistrationInit([]byte(testRecovery)).Serialize()
	}

	start, err := f.service.RegisterStart(
		context.Background(),
		username,
		passwordRequest.Serialize(),
		recoveryRequest,
	)
	if err != nil {
		t.Fatalf("RegisterStart: %v", err)
	}

	passwordRecord := registrationRecord(
		t,
		passwordClient,
		start.PasswordResponse,
		[]byte(username),
	)

	var recoveryRecord []byte
	blobs := validBlobs()

	if withRecovery {
		recoveryRecord = registrationRecord(
			t,
			recoveryClient,
			start.RecoveryResponse,
			[]byte(username),
		)

		blobs = append(blobs, BlobUpload{
			Kind:    store.BlobKindRecovery,
			Version: 1,
			Data:    bytes.Repeat([]byte{4}, 41),
		})
	}

	return RegisterFinishRequest{
		UserID:         start.UserID,
		Username:       username,
		PasswordRecord: passwordRecord,
		RecoveryRecord: recoveryRecord,
		Blobs:          blobs,
		PublicKeys:     validPublicKeys(),
	}, start
}

func TestRegisterStartRejectsInvalidUsername(t *testing.T) {
	f := newRegistrationFixture(t)

	for _, username := range []string{
		"",
		"ab",
		"UPPERCASE",
		"contains-hyphen",
		"contains space",
	} {
		t.Run(username, func(t *testing.T) {
			_, err := f.service.RegisterStart(
				context.Background(),
				username,
				[]byte("request"),
				nil,
			)

			if !errors.Is(err, ErrInvalidUsername) {
				t.Fatalf("RegisterStart error = %v, want ErrInvalidUsername", err)
			}
		})
	}
}

func TestRegisterStartRejectsTakenUsername(t *testing.T) {
	f := newRegistrationFixture(t)

	_, _ = f.validFinishRequest(t, testUsername, false)

	// The helper above reserves the username. A second reservation must fail.
	_, err := f.service.RegisterStart(
		context.Background(),
		testUsername,
		[]byte("malformed request"),
		nil,
	)

	if !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("RegisterStart error = %v, want ErrUsernameTaken", err)
	}
}

func TestRegisterStartRejectsMalformedRequest(t *testing.T) {
	f := newRegistrationFixture(t)

	_, err := f.service.RegisterStart(
		context.Background(),
		testUsername,
		[]byte("malformed request"),
		nil,
	)

	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RegisterStart error = %v, want ErrInvalidRequest", err)
	}
}

func TestRegisterFinishWithoutRecovery(t *testing.T) {
	f := newRegistrationFixture(t)

	req, _ := f.validFinishRequest(t, testUsername, false)

	if err := f.service.RegisterFinish(context.Background(), req); err != nil {
		t.Fatalf("RegisterFinish: %v", err)
	}

	user, err := f.store.UserByUsername(context.Background(), testUsername)
	if err != nil {
		t.Fatalf("UserByUsername: %v", err)
	}

	if !bytes.Equal(user.ID, req.UserID) {
		t.Fatal("stored user ID differs from registration user ID")
	}

	if _, err := f.store.CurrentOpaqueRecord(
		context.Background(),
		req.UserID,
		"password",
	); err != nil {
		t.Fatalf("password record not stored: %v", err)
	}

	if _, err := f.store.CurrentOpaqueRecord(
		context.Background(),
		req.UserID,
		"recovery",
	); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("recovery record lookup error = %v, want ErrNotFound", err)
	}

	for _, kind := range []byte{
		store.BlobKindKEK,
		store.BlobKindMEK,
		store.BlobKindIdentity,
	} {
		if _, err := f.store.CurrentBlob(context.Background(), req.UserID, kind); err != nil {
			t.Errorf("blob kind %d not stored: %v", kind, err)
		}
	}

	if _, err := f.store.CurrentBlob(
		context.Background(),
		req.UserID,
		store.BlobKindRecovery,
	); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("recovery blob lookup error = %v, want ErrNotFound", err)
	}
}

func TestRegisterFinishWithRecovery(t *testing.T) {
	f := newRegistrationFixture(t)

	req, start := f.validFinishRequest(t, testUsername, true)

	if len(start.RecoveryResponse) == 0 {
		t.Fatal("RegisterStart returned an empty recovery response")
	}

	if bytes.Equal(start.PasswordResponse, start.RecoveryResponse) {
		t.Fatal("password and recovery registration responses are identical")
	}

	if err := f.service.RegisterFinish(context.Background(), req); err != nil {
		t.Fatalf("RegisterFinish: %v", err)
	}

	for _, kind := range []string{"password", "recovery"} {
		if _, err := f.store.CurrentOpaqueRecord(
			context.Background(),
			req.UserID,
			kind,
		); err != nil {
			t.Errorf("%s record not stored: %v", kind, err)
		}
	}

	if _, err := f.store.CurrentBlob(
		context.Background(),
		req.UserID,
		store.BlobKindRecovery,
	); err != nil {
		t.Fatalf("recovery blob not stored: %v", err)
	}
}

func TestRegisterFinishRejectsWrongUserID(t *testing.T) {
	f := newRegistrationFixture(t)

	req, _ := f.validFinishRequest(t, testUsername, false)
	req.UserID = bytes.Repeat([]byte{0xA5}, 16)

	err := f.service.RegisterFinish(context.Background(), req)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RegisterFinish error = %v, want ErrInvalidRequest", err)
	}
}

func TestRegisterFinishRejectsWrongUserIDLength(t *testing.T) {
	f := newRegistrationFixture(t)

	req, _ := f.validFinishRequest(t, testUsername, false)
	req.UserID = req.UserID[:15]

	err := f.service.RegisterFinish(context.Background(), req)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RegisterFinish error = %v, want ErrInvalidRequest", err)
	}
}

func TestRegisterFinishRejectsExpiredReservation(t *testing.T) {
	f := newRegistrationFixture(t)

	req, _ := f.validFinishRequest(t, testUsername, false)

	f.now = f.now.Add(registrationReservationLifetime + time.Nanosecond)

	err := f.service.RegisterFinish(context.Background(), req)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RegisterFinish error = %v, want ErrInvalidRequest", err)
	}

	if _, err := f.store.UserByUsername(context.Background(), testUsername); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("UserByUsername error = %v, want ErrNotFound", err)
	}
}

func TestRegisterFinishRejectsMissingKEK(t *testing.T) {
	f := newRegistrationFixture(t)

	req, _ := f.validFinishRequest(t, testUsername, false)
	req.Blobs = req.Blobs[1:]

	err := f.service.RegisterFinish(context.Background(), req)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RegisterFinish error = %v, want ErrInvalidRequest", err)
	}
}

func TestRegisterFinishRejectsWrongBlobVersion(t *testing.T) {
	f := newRegistrationFixture(t)

	req, _ := f.validFinishRequest(t, testUsername, false)
	req.Blobs[0].Version = 2

	err := f.service.RegisterFinish(context.Background(), req)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RegisterFinish error = %v, want ErrInvalidRequest", err)
	}
}

func TestRegisterFinishRejectsOversizedBlob(t *testing.T) {
	f := newRegistrationFixture(t)

	req, _ := f.validFinishRequest(t, testUsername, false)
	req.Blobs[0].Data = bytes.Repeat([]byte{1}, 4097)

	err := f.service.RegisterFinish(context.Background(), req)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RegisterFinish error = %v, want ErrInvalidRequest", err)
	}
}

func TestRegisterFinishRejectsMalformedPasswordRecord(t *testing.T) {
	f := newRegistrationFixture(t)

	req, _ := f.validFinishRequest(t, testUsername, false)
	req.PasswordRecord = []byte("not an OPAQUE registration record")

	err := f.service.RegisterFinish(context.Background(), req)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RegisterFinish error = %v, want ErrInvalidRequest", err)
	}
}

func TestRegisterFinishRejectsMalformedRecoveryRecord(t *testing.T) {
	f := newRegistrationFixture(t)

	req, _ := f.validFinishRequest(t, testUsername, true)
	req.RecoveryRecord = []byte("not an OPAQUE registration record")

	err := f.service.RegisterFinish(context.Background(), req)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RegisterFinish error = %v, want ErrInvalidRequest", err)
	}
}

func TestRegisterFinishRejectsMissingRecoveryBlob(t *testing.T) {
	f := newRegistrationFixture(t)

	req, _ := f.validFinishRequest(t, testUsername, true)

	for i, blob := range req.Blobs {
		if blob.Kind == store.BlobKindRecovery {
			req.Blobs = append(req.Blobs[:i], req.Blobs[i+1:]...)
			break
		}
	}

	err := f.service.RegisterFinish(context.Background(), req)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RegisterFinish error = %v, want ErrInvalidRequest", err)
	}
}

func TestRegisterFinishRejectsRecoveryBlobWithoutRecoveryRecord(t *testing.T) {
	f := newRegistrationFixture(t)

	req, _ := f.validFinishRequest(t, testUsername, false)
	req.Blobs = append(req.Blobs, BlobUpload{
		Kind:    store.BlobKindRecovery,
		Version: 1,
		Data:    bytes.Repeat([]byte{4}, 41),
	})

	err := f.service.RegisterFinish(context.Background(), req)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RegisterFinish error = %v, want ErrInvalidRequest", err)
	}
}

func TestRegisterFinishRejectsDuplicateCompletion(t *testing.T) {
	f := newRegistrationFixture(t)

	req, _ := f.validFinishRequest(t, testUsername, false)

	if err := f.service.RegisterFinish(context.Background(), req); err != nil {
		t.Fatalf("first RegisterFinish: %v", err)
	}

	err := f.service.RegisterFinish(context.Background(), req)
	if !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("second RegisterFinish error = %v, want ErrUsernameTaken", err)
	}
}

func TestRegisterFinishRejectsInvalidPublicKey(t *testing.T) {
	f := newRegistrationFixture(t)

	req, _ := f.validFinishRequest(t, testUsername, false)
	req.PublicKeys = []PublicKeyUpload{
		{Kind: "unknown", Key: []byte{1}},
	}

	err := f.service.RegisterFinish(context.Background(), req)
	if !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("RegisterFinish error = %v, want ErrInvalidRequest", err)
	}
}
