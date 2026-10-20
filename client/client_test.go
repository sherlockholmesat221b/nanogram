// File: client/client_test.go

package client

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/auth"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/service"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/store/memstore"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/wire"
	"gitlab.com/sherlockholmesat221b/nanogram/internal/zkcrypto"
)

// direct is a Transport that calls the service in the same process.
type direct struct {
	svc *service.Service
}

func (d direct) RegisterStart(ctx context.Context, username string, p, r []byte) (service.RegisterStartResult, error) {
	return d.svc.RegisterStart(ctx, username, p, r)
}

func (d direct) RegisterFinish(ctx context.Context, r service.RegisterFinishRequest) error {
	return d.svc.RegisterFinish(ctx, r)
}

func (d direct) LoginStart(ctx context.Context, username, kind string, ke1 []byte) (service.LoginStartResult, error) {
	return d.svc.LoginStart(ctx, username, kind, ke1)
}

func (d direct) LoginFinish(ctx context.Context, loginID, ke3 []byte) (service.SessionInfo, error) {
	return d.svc.LoginFinish(ctx, loginID, ke3)
}

// AccountBlobs does what the HTTP handler does: authenticate, then read.
func (d direct) AccountBlobs(ctx context.Context, r service.AuthRequest) ([]service.BlobInfo, error) {
	session, err := d.svc.Authenticate(ctx, r, "full")
	if err != nil {
		return nil, err
	}

	return d.svc.CurrentBlobs(ctx, session.UserID, store.BlobKindKEK, store.BlobKindMEK, store.BlobKindIdentity)
}

// counting counts how often the server was contacted for a registration.
type counting struct {
	Transport
	registerStarts int
}

func (c *counting) RegisterStart(ctx context.Context, username string, p, r []byte) (service.RegisterStartResult, error) {
	c.registerStarts++
	return c.Transport.RegisterStart(ctx, username, p, r)
}

// tampering changes the blobs the server returns.
type tampering struct {
	Transport
	change func([]service.BlobInfo) []service.BlobInfo
}

func (t tampering) AccountBlobs(ctx context.Context, r service.AuthRequest) ([]service.BlobInfo, error) {
	blobs, err := t.Transport.AccountBlobs(ctx, r)
	if err != nil {
		return nil, err
	}

	return t.change(blobs), nil
}

type rig struct {
	svc    *service.Service
	store  *memstore.MemStore
	heads  HeadStore
	client *Client
	now    time.Time
}

func newRig(t *testing.T) *rig {
	t.Helper()

	conf := auth.NewConfiguration()
	keys := auth.GenerateServerKeys(conf)
	m := memstore.New()

	r := &rig{
		store: m,
		heads: NewMemHeads(),
		now:   time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC),
	}

	r.svc = service.New(service.Config{
		Auth:  auth.NewServer(keys),
		Store: m,
		Now: func() time.Time {
			return r.now
		},
	})
	r.client = New(direct{r.svc}, r.heads)

	return r
}

func newPassphrase(t *testing.T) string {
	t.Helper()

	p, err := GeneratePassphrase(DefaultPassphraseWords)
	if err != nil {
		t.Fatal(err)
	}

	return p
}

// register creates the account "alice" and returns its passphrase and result.
func (r *rig) register(t *testing.T, withRecovery bool) (string, RegisterResult) {
	t.Helper()

	passphrase := newPassphrase(t)

	result, err := r.client.Register(context.Background(), "alice", passphrase, passphrase, withRecovery)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	return passphrase, result
}

func (r *rig) login(t *testing.T, passphrase string) *Session {
	t.Helper()

	session, err := r.client.Login(context.Background(), "alice", passphrase)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}

	return session
}

func TestRegisterAndLogin(t *testing.T) {
	r := newRig(t)
	passphrase, result := r.register(t, true)

	first := r.login(t, passphrase)
	second := r.login(t, passphrase)

	if !bytes.Equal(first.UserID, result.UserID) {
		t.Fatal("the session belongs to another user id")
	}
	if first.Scope != "full" {
		t.Fatalf("scope = %q", first.Scope)
	}

	a, b := first.Account, second.Account
	if len(a.KEK) != 32 || len(a.MEK) != 32 || len(a.MLKEMSeed) != 64 || len(a.SignSeed) != 32 {
		t.Fatalf("unexpected secret sizes %d %d %d %d", len(a.KEK), len(a.MEK), len(a.MLKEMSeed), len(a.SignSeed))
	}
	if !bytes.Equal(a.KEK, b.KEK) || !bytes.Equal(a.MEK, b.MEK) ||
		!bytes.Equal(a.MLKEMSeed, b.MLKEMSeed) || !bytes.Equal(a.SignSeed, b.SignSeed) {
		t.Fatal("two logins opened different secrets")
	}
	if bytes.Equal(a.KEK, a.MEK) {
		t.Fatal("the KEK and the MEK are equal")
	}
	if len(first.Warnings) != 0 || len(second.Warnings) != 0 {
		t.Fatalf("unexpected warnings %v %v", first.Warnings, second.Warnings)
	}
}

func TestPublicKeysAreStored(t *testing.T) {
	r := newRig(t)
	_, result := r.register(t, false)

	for _, kind := range []string{"mlkem", "sign"} {
		keys, err := r.store.PublicKeys(context.Background(), result.UserID, kind)
		if err != nil || len(keys) != 1 {
			t.Fatalf("%s keys: %v, %v", kind, keys, err)
		}
	}
}

func TestRecoveryPhraseUnlocksTheKEK(t *testing.T) {
	r := newRig(t)
	passphrase, result := r.register(t, true)

	if len(strings.Fields(result.RecoveryPhrase)) != 24 {
		t.Fatalf("recovery phrase has %d words", len(strings.Fields(result.RecoveryPhrase)))
	}

	key, err := zkcrypto.RecoveryKeyFromPhrase(result.RecoveryPhrase)
	if err != nil {
		t.Fatal(err)
	}

	wrap, err := zkcrypto.RecoveryWrapKey(key)
	if err != nil {
		t.Fatal(err)
	}

	blob, err := r.store.CurrentBlob(context.Background(), result.UserID, store.BlobKindRecovery)
	if err != nil {
		t.Fatal(err)
	}

	kek, err := zkcrypto.OpenBlob(wrap, blob.Data, result.UserID, zkcrypto.KindRecovery, blob.Version, blob.PrevHash)
	if err != nil {
		t.Fatalf("the recovery phrase does not open the recovery blob: %v", err)
	}

	session := r.login(t, passphrase)
	if !bytes.Equal(kek, session.Account.KEK) {
		t.Fatal("the recovery blob holds a different KEK than the password blob")
	}
}

func TestRegisterWithoutRecovery(t *testing.T) {
	r := newRig(t)
	passphrase, result := r.register(t, false)

	if result.RecoveryPhrase != "" {
		t.Fatal("a recovery phrase was returned")
	}

	if _, err := r.store.CurrentBlob(context.Background(), result.UserID, store.BlobKindRecovery); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("recovery blob: %v", err)
	}

	r.login(t, passphrase)
}

func TestWrongPassphraseAndUnknownUserLookTheSame(t *testing.T) {
	r := newRig(t)
	passphrase, _ := r.register(t, false)

	_, wrong := r.client.Login(context.Background(), "alice", newPassphrase(t))
	_, unknown := r.client.Login(context.Background(), "mallory", passphrase)

	if !errors.Is(wrong, ErrLoginFailed) || !errors.Is(unknown, ErrLoginFailed) {
		t.Fatalf("errors: %v and %v", wrong, unknown)
	}
	if wrong.Error() != unknown.Error() {
		t.Fatalf("different messages: %q and %q", wrong, unknown)
	}
}

func TestTakenUsernameIsReported(t *testing.T) {
	r := newRig(t)
	r.register(t, false)

	passphrase := newPassphrase(t)
	_, err := r.client.Register(context.Background(), "alice", passphrase, passphrase, false)
	if !errors.Is(err, service.ErrUsernameTaken) {
		t.Fatalf("error = %v, want ErrUsernameTaken", err)
	}
}

func TestBadPassphrasesNeverReachTheServer(t *testing.T) {
	r := newRig(t)
	counter := &counting{Transport: direct{r.svc}}
	c := New(counter, nil)

	good := newPassphrase(t)

	tests := []struct {
		name       string
		passphrase string
		confirm    string
		want       error
	}{
		{"typo in the confirmation", good, good + " extra", ErrPassphraseMismatch},
		{"a custom passphrase", "correct horse battery staple", "correct horse battery staple", ErrWeakPassphrase},
		{"too few words", "abandon ability able about above", "abandon ability able about above", ErrWeakPassphrase},
		{"empty", "", "", ErrWeakPassphrase},
	}

	for _, tt := range tests {
		_, err := c.Register(context.Background(), "alice", tt.passphrase, tt.confirm, true)
		if !errors.Is(err, tt.want) {
			t.Fatalf("%s: error = %v, want %v", tt.name, err, tt.want)
		}
	}

	if counter.registerStarts != 0 {
		t.Fatalf("the server was contacted %d times", counter.registerStarts)
	}
}

func TestSpellingOfThePassphraseDoesNotMatter(t *testing.T) {
	r := newRig(t)
	passphrase := newPassphrase(t)

	typed := "  " + strings.ToUpper(strings.ReplaceAll(passphrase, " ", "   ")) + " \n"

	if _, err := r.client.Register(context.Background(), "alice", typed, passphrase, false); err != nil {
		t.Fatalf("Register: %v", err)
	}

	r.login(t, passphrase)
	r.login(t, typed)
}

func TestCheckHead(t *testing.T) {
	known := Head{Version: 3, Hash: [32]byte{1}}

	tests := []struct {
		name        string
		seen        bool
		version     uint64
		prev        [32]byte
		hash        [32]byte
		wantErr     error
		wantWarning bool
	}{
		{"first time", false, 1, [32]byte{}, [32]byte{9}, nil, false},
		{"same", true, 3, [32]byte{5}, [32]byte{1}, nil, false},
		{"older", true, 2, [32]byte{}, [32]byte{1}, ErrRollback, false},
		{"same version, other hash", true, 3, [32]byte{5}, [32]byte{2}, ErrTamper, false},
		{"next version, chained", true, 4, [32]byte{1}, [32]byte{2}, nil, true},
		{"next version, not chained", true, 4, [32]byte{7}, [32]byte{2}, ErrTamper, false},
		{"two versions ahead", true, 5, [32]byte{7}, [32]byte{2}, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning, err := checkHead(known, tt.seen, tt.version, tt.prev, tt.hash)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			if (warning != "") != tt.wantWarning {
				t.Fatalf("warning = %q", warning)
			}
		})
	}
}

func TestRollbackAndTamperingAreDetected(t *testing.T) {
	r := newRig(t)
	passphrase, result := r.register(t, false)

	kek := byte(zkcrypto.KindKEK)

	// The device saw a newer KEK before than the server now returns.
	if err := r.heads.Put(result.UserID, kek, Head{Version: 2, Hash: [32]byte{1}}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.client.Login(context.Background(), "alice", passphrase); !errors.Is(err, ErrRollback) {
		t.Fatalf("rollback: error = %v", err)
	}

	// The device saw other data for the same version.
	if err := r.heads.Put(result.UserID, kek, Head{Version: 1, Hash: [32]byte{9}}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.client.Login(context.Background(), "alice", passphrase); !errors.Is(err, ErrTamper) {
		t.Fatalf("tampering: error = %v", err)
	}

	// A device that has seen nothing cannot notice either, and logs in.
	fresh := New(direct{r.svc}, NewMemHeads())
	if _, err := fresh.Login(context.Background(), "alice", passphrase); err != nil {
		t.Fatalf("fresh device: %v", err)
	}
}

func TestChangedBlobsAreRejected(t *testing.T) {
	r := newRig(t)
	passphrase, result := r.register(t, false)

	find := func(blobs []service.BlobInfo, kind zkcrypto.BlobKind) int {
		for i, b := range blobs {
			if b.Kind == byte(kind) {
				return i
			}
		}
		return -1
	}

	// A device that remembers the blobs catches most changes through the head
	// check. A device that remembers nothing has to rely on the keys alone.
	tests := []struct {
		name      string
		change    func([]service.BlobInfo) []service.BlobInfo
		wantKnown error
		wantFresh error
	}{
		{"flipped byte", func(b []service.BlobInfo) []service.BlobInfo {
			i := find(b, zkcrypto.KindKEK)
			b[i].Data = bytes.Clone(b[i].Data)
			b[i].Data[len(b[i].Data)-1] ^= 1
			return b
		}, ErrTamper, ErrBlobRejected},
		{"swapped kinds", func(b []service.BlobInfo) []service.BlobInfo {
			i := find(b, zkcrypto.KindKEK)
			j := find(b, zkcrypto.KindMEK)
			b[i].Kind, b[j].Kind = b[j].Kind, b[i].Kind
			return b
		}, ErrTamper, ErrBlobRejected},
		{"wrong version", func(b []service.BlobInfo) []service.BlobInfo {
			i := find(b, zkcrypto.KindKEK)
			b[i].Version++
			return b
		}, ErrTamper, ErrBlobRejected},
		{"wrong previous hash", func(b []service.BlobInfo) []service.BlobInfo {
			i := find(b, zkcrypto.KindMEK)
			b[i].PrevHash = [32]byte{1}
			return b
		}, ErrTamper, ErrBlobRejected},
		{"missing blob", func(b []service.BlobInfo) []service.BlobInfo {
			i := find(b, zkcrypto.KindIdentity)
			return append(b[:i], b[i+1:]...)
		}, ErrBadBlobs, ErrBadBlobs},
		{"repeated blob", func(b []service.BlobInfo) []service.BlobInfo {
			return append(b, b[0])
		}, ErrBadBlobs, ErrBadBlobs},
		{"unknown kind", func(b []service.BlobInfo) []service.BlobInfo {
			return append(b, service.BlobInfo{Kind: 9})
		}, ErrBadBlobs, ErrBadBlobs},
	}

	kek := byte(zkcrypto.KindKEK)
	known, _ := r.heads.Get(result.UserID, kek)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(tampering{Transport: direct{r.svc}, change: tt.change}, r.heads)

			if _, err := c.Login(context.Background(), "alice", passphrase); !errors.Is(err, tt.wantKnown) {
				t.Fatalf("device with memory: error = %v, want %v", err, tt.wantKnown)
			}
			if after, _ := r.heads.Get(result.UserID, kek); after != known {
				t.Fatal("a refused login changed the remembered head")
			}

			fresh := NewMemHeads()
			c = New(tampering{Transport: direct{r.svc}, change: tt.change}, fresh)

			if _, err := c.Login(context.Background(), "alice", passphrase); !errors.Is(err, tt.wantFresh) {
				t.Fatalf("fresh device: error = %v, want %v", err, tt.wantFresh)
			}
			if _, seen := fresh.Get(result.UserID, kek); seen {
				t.Fatal("a refused login was remembered")
			}
		})
	}
}

func TestSessionSignsEveryRequestOnce(t *testing.T) {
	r := newRig(t)
	passphrase, _ := r.register(t, false)
	session := r.login(t, passphrase)

	d := direct{r.svc}

	first := session.Sign("GET", wire.PathAccountBlobs, nil)
	second := session.Sign("GET", wire.PathAccountBlobs, nil)

	if first.Counter != 2 || second.Counter != 3 {
		// Login already used counter 1 for the blob request.
		t.Fatalf("counters %d and %d", first.Counter, second.Counter)
	}

	for _, request := range []service.AuthRequest{first, second} {
		blobs, err := d.AccountBlobs(context.Background(), request)
		if err != nil || len(blobs) != 3 {
			t.Fatalf("signed request: %d blobs, %v", len(blobs), err)
		}
	}

	if _, err := d.AccountBlobs(context.Background(), first); !errors.Is(err, service.ErrUnauthorized) {
		t.Fatalf("replayed request: error = %v, want ErrUnauthorized", err)
	}
}

func TestWipeClearsTheSecrets(t *testing.T) {
	r := newRig(t)
	passphrase, _ := r.register(t, false)
	session := r.login(t, passphrase)

	account := session.Account
	session.Wipe()

	for name, secret := range map[string][]byte{
		"KEK": account.KEK, "MEK": account.MEK,
		"ML-KEM seed": account.MLKEMSeed, "signing seed": account.SignSeed,
	} {
		if !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatalf("%s was not wiped", name)
		}
	}

	if session.requestKey != nil {
		t.Fatal("the request key was not wiped")
	}
}
