package memstore

import (
	"bytes"
	"context"
	"sort"
	"sync"
	"time"

	"gitlab.com/sherlockholmesat221b/nanogram/internal/store"
)

type reservation struct {
	userID  []byte
	expires time.Time
}

type opaqueKey struct {
	userID  string
	kind    string
	pending bool
}

type blobKey struct {
	userID  string
	kind    byte
	version uint64
}

type pubKeyKey struct {
	userID  string
	kind    string
	version uint32
}

type MemStore struct {
	mu           sync.Mutex
	usersByName  map[string]store.User
	usersByID    map[string]store.User
	reservations map[string]reservation
	opaque       map[opaqueKey]store.OpaqueRecord
	blobs        map[blobKey]store.Blob
	pubKeys      map[pubKeyKey]store.PublicKey
	expiries     map[string]time.Time // userID string -> pending expiry time
	loginStates  map[[32]byte]store.LoginState
	sessions     map[[32]byte]store.Session
}

func New() *MemStore {
	return &MemStore{
		usersByName:  make(map[string]store.User),
		usersByID:    make(map[string]store.User),
		reservations: make(map[string]reservation),
		opaque:       make(map[opaqueKey]store.OpaqueRecord),
		blobs:        make(map[blobKey]store.Blob),
		pubKeys:      make(map[pubKeyKey]store.PublicKey),
		expiries:     make(map[string]time.Time),
		loginStates:  make(map[[32]byte]store.LoginState),
		sessions:     make(map[[32]byte]store.Session),
	}
}

var _ store.Store = (*MemStore)(nil)

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

func clone(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

func cloneUser(u store.User) store.User {
	u.ID = clone(u.ID)
	return u
}

func cloneOpaque(r store.OpaqueRecord) store.OpaqueRecord {
	r.UserID = clone(r.UserID)
	r.Record = clone(r.Record)
	return r
}

func cloneBlob(b store.Blob) store.Blob {
	b.UserID = clone(b.UserID)
	b.Data = clone(b.Data)
	return b
}

func clonePublicKey(p store.PublicKey) store.PublicKey {
	p.UserID = clone(p.UserID)
	p.Key = clone(p.Key)
	return p
}

func cloneSession(s store.Session) store.Session {
	s.UserID = clone(s.UserID)
	s.Key = clone(s.Key)
	return s
}

func cloneLoginState(s store.LoginState) store.LoginState {
	s.State = clone(s.State)
	return s
}

func (m *MemStore) ReserveUsername(
	ctx context.Context,
	username string,
	userID []byte,
	now, until time.Time,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.usersByName[username]; ok {
		return store.ErrTaken
	}

	if r, ok := m.reservations[username]; ok && r.expires.After(now) {
		return store.ErrTaken
	}

	m.reservations[username] = reservation{
		userID:  clone(userID),
		expires: until,
	}

	return nil
}

func (m *MemStore) CreateUser(
	ctx context.Context,
	u store.User,
	records []store.OpaqueRecord,
	blobs []store.Blob,
	keys []store.PublicKey,
	now time.Time,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.usersByName[u.Username]; ok {
		return store.ErrTaken
	}

	r, ok := m.reservations[u.Username]
	if !ok || !r.expires.After(now) || !bytes.Equal(r.userID, u.ID) {
		return store.ErrConflict
	}

	id := string(u.ID)
	if _, exists := m.usersByID[id]; exists {
		return store.ErrConflict
	}

	// Validate all input before mutating any stored state
	seenOpaque := make(map[opaqueKey]struct{}, len(records))
	for _, rec := range records {
		if !bytes.Equal(rec.UserID, u.ID) ||
			rec.Pending ||
			(rec.Kind != "password" && rec.Kind != "recovery") {
			return store.ErrConflict
		}

		key := opaqueKey{
			userID:  id,
			kind:    rec.Kind,
			pending: false,
		}

		if _, exists := m.opaque[key]; exists {
			return store.ErrConflict
		}
		if _, exists := seenOpaque[key]; exists {
			return store.ErrConflict
		}
		seenOpaque[key] = struct{}{}
	}

	seenBlobs := make(map[blobKey]struct{}, len(blobs))
	for _, b := range blobs {
		if !bytes.Equal(b.UserID, u.ID) || b.Pending {
			return store.ErrConflict
		}

		key := blobKey{
			userID:  id,
			kind:    b.Kind,
			version: b.Version,
		}

		if _, exists := m.blobs[key]; exists {
			return store.ErrConflict
		}
		if _, exists := seenBlobs[key]; exists {
			return store.ErrConflict
		}
		seenBlobs[key] = struct{}{}
	}

	seenKeys := make(map[pubKeyKey]struct{}, len(keys))
	for _, pk := range keys {
		if !bytes.Equal(pk.UserID, u.ID) ||
			(pk.Kind != "mlkem" && pk.Kind != "sign") ||
			pk.Version != 1 ||
			len(pk.Key) < 1 ||
			len(pk.Key) > 2048 {
			return store.ErrConflict
		}

		key := pubKeyKey{
			userID:  id,
			kind:    pk.Kind,
			version: pk.Version,
		}

		if _, exists := m.pubKeys[key]; exists {
			return store.ErrConflict
		}
		if _, exists := seenKeys[key]; exists {
			return store.ErrConflict
		}
		seenKeys[key] = struct{}{}
	}

	cu := cloneUser(u)
	m.usersByName[u.Username] = cu
	m.usersByID[id] = cu

	for _, rec := range records {
		key := opaqueKey{
			userID:  id,
			kind:    rec.Kind,
			pending: false,
		}
		m.opaque[key] = cloneOpaque(rec)
	}

	for _, b := range blobs {
		key := blobKey{
			userID:  id,
			kind:    b.Kind,
			version: b.Version,
		}
		m.blobs[key] = cloneBlob(b)
	}

	for _, pk := range keys {
		key := pubKeyKey{
			userID:  id,
			kind:    pk.Kind,
			version: pk.Version,
		}
		cp := clonePublicKey(pk)
		cp.CreatedAt = now
		m.pubKeys[key] = cp
	}

	delete(m.reservations, u.Username)
	return nil
}

func (m *MemStore) UserByUsername(
	ctx context.Context,
	username string,
) (store.User, error) {
	if err := checkContext(ctx); err != nil {
		return store.User{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	u, ok := m.usersByName[username]
	if !ok {
		return store.User{}, store.ErrNotFound
	}

	return cloneUser(u), nil
}

func (m *MemStore) CurrentOpaqueRecord(
	ctx context.Context,
	userID []byte,
	kind string,
) (store.OpaqueRecord, error) {
	if err := checkContext(ctx); err != nil {
		return store.OpaqueRecord{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := opaqueKey{
		userID:  string(userID),
		kind:    kind,
		pending: false,
	}

	r, ok := m.opaque[key]
	if !ok {
		return store.OpaqueRecord{}, store.ErrNotFound
	}

	return cloneOpaque(r), nil
}

func (m *MemStore) CurrentBlob(
	ctx context.Context,
	userID []byte,
	kind byte,
) (store.Blob, error) {
	if err := checkContext(ctx); err != nil {
		return store.Blob{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	var best store.Blob
	found := false

	for key, b := range m.blobs {
		if key.userID != string(userID) ||
			key.kind != kind ||
			b.Pending {
			continue
		}

		if !found || b.Version > best.Version {
			best = b
			found = true
		}
	}

	if !found {
		return store.Blob{}, store.ErrNotFound
	}

	return cloneBlob(best), nil
}

func (m *MemStore) hasPendingPasswordChange(
	userID []byte,
	now time.Time,
) bool {
	id := string(userID)

	if _, ok := m.opaque[opaqueKey{
		userID:  id,
		kind:    "password",
		pending: true,
	}]; ok {
		until, exists := m.expiries[id]
		if exists && until.After(now) {
			return true
		}
	}

	for key, b := range m.blobs {
		if key.userID != id ||
			key.kind != store.BlobKindKEK ||
			!b.Pending {
			continue
		}

		until, exists := m.expiries[id]
		if exists && until.After(now) {
			return true
		}
	}

	return false
}

func (m *MemStore) BeginPasswordChange(
	ctx context.Context,
	userID []byte,
	expectedKEKVersion uint64,
	rec store.OpaqueRecord,
	kek store.Blob,
	now, until time.Time,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if m.hasPendingPasswordChange(userID, now) {
		return store.ErrConflict
	}

	id := string(userID)

	delete(m.opaque, opaqueKey{
		userID:  id,
		kind:    "password",
		pending: true,
	})
	for key, b := range m.blobs {
		if key.userID == id &&
			key.kind == store.BlobKindKEK &&
			b.Pending {
			delete(m.blobs, key)
		}
	}
	delete(m.expiries, id)

	var current store.Blob
	found := false

	for key, b := range m.blobs {
		if key.userID != id ||
			key.kind != store.BlobKindKEK ||
			b.Pending {
			continue
		}

		if !found || b.Version > current.Version {
			current = b
			found = true
		}
	}

	if !found || current.Version != expectedKEKVersion {
		return store.ErrConflict
	}

	if expectedKEKVersion == ^uint64(0) ||
		kek.Version != expectedKEKVersion+1 {
		return store.ErrConflict
	}

	if !bytes.Equal(rec.UserID, userID) ||
		rec.Kind != "password" ||
		!rec.Pending ||
		!bytes.Equal(kek.UserID, userID) ||
		kek.Kind != store.BlobKindKEK ||
		!kek.Pending {
		return store.ErrConflict
	}

	opaqueKey := opaqueKey{
		userID:  id,
		kind:    "password",
		pending: true,
	}
	newBlobKey := blobKey{
		userID:  id,
		kind:    kek.Kind,
		version: kek.Version,
	}

	if _, exists := m.opaque[opaqueKey]; exists {
		return store.ErrConflict
	}
	if _, exists := m.blobs[newBlobKey]; exists {
		return store.ErrConflict
	}

	m.opaque[opaqueKey] = cloneOpaque(rec)
	m.blobs[newBlobKey] = cloneBlob(kek)
	m.expiries[id] = until

	return nil
}

func (m *MemStore) CommitPasswordChange(
	ctx context.Context,
	userID []byte,
	now time.Time,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := string(userID)
	pendingOpaqueKey := opaqueKey{
		userID:  id,
		kind:    "password",
		pending: true,
	}

	pendingRec, foundRecord := m.opaque[pendingOpaqueKey]

	var pendingBlobKey blobKey
	foundBlob := false

	for key, b := range m.blobs {
		if key.userID == id &&
			key.kind == store.BlobKindKEK &&
			b.Pending {
			pendingBlobKey = key
			foundBlob = true
			break
		}
	}

	until, foundExpiry := m.expiries[id]
	if !foundRecord || !foundBlob || !foundExpiry || !until.After(now) {
		return store.ErrNotFound
	}

	delete(m.opaque, pendingOpaqueKey)
	pendingRec.Pending = false
	m.opaque[opaqueKey{
		userID:  id,
		kind:    "password",
		pending: false,
	}] = cloneOpaque(pendingRec)

	pendingBlob := m.blobs[pendingBlobKey]
	pendingBlob.Pending = false
	m.blobs[pendingBlobKey] = cloneBlob(pendingBlob)
	delete(m.expiries, id)

	return nil
}

func (m *MemStore) AbortPasswordChange(
	ctx context.Context,
	userID []byte,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := string(userID)
	pendingOpaqueKey := opaqueKey{
		userID:  id,
		kind:    "password",
		pending: true,
	}

	found := false

	if _, ok := m.opaque[pendingOpaqueKey]; ok {
		delete(m.opaque, pendingOpaqueKey)
		found = true
	}

	for key, b := range m.blobs {
		if key.userID == id &&
			key.kind == store.BlobKindKEK &&
			b.Pending {
			delete(m.blobs, key)
			found = true
		}
	}

	if !found {
		return store.ErrNotFound
	}

	delete(m.expiries, id)
	return nil
}

func (m *MemStore) AppendBlob(
	ctx context.Context,
	b store.Blob,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := string(b.UserID)
	if _, exists := m.usersByID[id]; !exists {
		return store.ErrNotFound
	}

	if b.Pending {
		return store.ErrConflict
	}

	if b.Kind == store.BlobKindKEK ||
		b.Kind == store.BlobKindRecovery {
		return store.ErrConflict
	}

	var maxVer uint64
	hasAny := false

	for key, existing := range m.blobs {
		if key.userID == id && key.kind == b.Kind && !existing.Pending {
			hasAny = true
			if existing.Version > maxVer {
				maxVer = existing.Version
			}
		}
	}

	expectedVersion := uint64(1)
	if hasAny {
		expectedVersion = maxVer + 1
	}

	if b.Version != expectedVersion {
		return store.ErrConflict
	}

	key := blobKey{
		userID:  id,
		kind:    b.Kind,
		version: b.Version,
	}
	if _, exists := m.blobs[key]; exists {
		return store.ErrConflict
	}

	m.blobs[key] = cloneBlob(b)
	return nil
}

func (m *MemStore) ReplaceRecovery(
	ctx context.Context,
	userID []byte,
	rec store.OpaqueRecord,
	blob store.Blob,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := string(userID)
	if _, exists := m.usersByID[id]; !exists {
		return store.ErrNotFound
	}

	if rec.Pending || blob.Pending || rec.Kind != "recovery" || blob.Kind != store.BlobKindRecovery {
		return store.ErrConflict
	}
	if !bytes.Equal(rec.UserID, userID) || !bytes.Equal(blob.UserID, userID) {
		return store.ErrConflict
	}

	var maxVer uint64
	hasAny := false
	for key, existing := range m.blobs {
		if key.userID == id && key.kind == store.BlobKindRecovery && !existing.Pending {
			hasAny = true
			if existing.Version > maxVer {
				maxVer = existing.Version
			}
		}
	}

	expectedVersion := uint64(1)
	if hasAny {
		expectedVersion = maxVer + 1
	}

	if blob.Version != expectedVersion {
		return store.ErrConflict
	}

	// Delete old current recovery opaque record if any
	oldOpaqueKey := opaqueKey{
		userID:  id,
		kind:    "recovery",
		pending: false,
	}
	delete(m.opaque, oldOpaqueKey)

	newBlobKey := blobKey{
		userID:  id,
		kind:    blob.Kind,
		version: blob.Version,
	}
	if _, exists := m.blobs[newBlobKey]; exists {
		return store.ErrConflict
	}

	m.opaque[oldOpaqueKey] = cloneOpaque(rec)
	m.blobs[newBlobKey] = cloneBlob(blob)
	return nil
}

func (m *MemStore) DeleteRecovery(
	ctx context.Context,
	userID []byte,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := string(userID)
	oldOpaqueKey := opaqueKey{
		userID:  id,
		kind:    "recovery",
		pending: false,
	}

	if _, ok := m.opaque[oldOpaqueKey]; !ok {
		return store.ErrNotFound
	}

	delete(m.opaque, oldOpaqueKey)
	for key := range m.blobs {
		if key.userID == id && key.kind == store.BlobKindRecovery {
			delete(m.blobs, key)
		}
	}

	return nil
}

func (m *MemStore) PutPublicKey(
	ctx context.Context,
	userID []byte,
	kind string,
	version uint32,
	key []byte,
	now time.Time,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	if kind != "mlkem" && kind != "sign" {
		return store.ErrConflict
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := string(userID)
	if _, exists := m.usersByID[id]; !exists {
		return store.ErrNotFound
	}

	pkKey := pubKeyKey{
		userID:  id,
		kind:    kind,
		version: version,
	}

	if _, exists := m.pubKeys[pkKey]; exists {
		return store.ErrConflict
	}

	m.pubKeys[pkKey] = store.PublicKey{
		UserID:    clone(userID),
		Kind:      kind,
		Version:   version,
		Key:       clone(key),
		CreatedAt: now,
	}
	return nil
}

func (m *MemStore) PublicKeys(
	ctx context.Context,
	userID []byte,
	kind string,
) ([]store.PublicKey, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	id := string(userID)
	var list []store.PublicKey

	for pkKey, pk := range m.pubKeys {
		if pkKey.userID == id && pkKey.kind == kind {
			list = append(list, clonePublicKey(pk))
		}
	}

	if len(list) == 0 {
		return nil, store.ErrNotFound
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].Version < list[j].Version
	})

	return list, nil
}

func (m *MemStore) PutLoginState(
	ctx context.Context,
	ls store.LoginState,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.loginStates[ls.IDHash]; ok {
		return store.ErrConflict
	}

	m.loginStates[ls.IDHash] = cloneLoginState(ls)
	return nil
}

func (m *MemStore) TakeLoginState(
	ctx context.Context,
	idHash [32]byte,
	now time.Time,
) (store.LoginState, error) {
	if err := checkContext(ctx); err != nil {
		return store.LoginState{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	ls, ok := m.loginStates[idHash]
	if !ok {
		return store.LoginState{}, store.ErrNotFound
	}

	// Delete before returning, including when the state has expired
	delete(m.loginStates, idHash)

	if !ls.ExpiresAt.After(now) {
		return store.LoginState{}, store.ErrNotFound
	}

	return cloneLoginState(ls), nil
}

func (m *MemStore) PutSession(ctx context.Context, s store.Session) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	if s.Scope != "full" && s.Scope != "recovery" {
		return store.ErrConflict
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.sessions[s.IDHash]; ok {
		return store.ErrConflict
	}

	m.sessions[s.IDHash] = cloneSession(s)
	return nil
}

func (m *MemStore) SessionByIDHash(
	ctx context.Context,
	idHash [32]byte,
	now time.Time,
) (store.Session, error) {
	if err := checkContext(ctx); err != nil {
		return store.Session{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[idHash]
	if !ok || !s.ExpiresAt.After(now) {
		return store.Session{}, store.ErrNotFound
	}

	return cloneSession(s), nil
}

func (m *MemStore) AdvanceCounter(
	ctx context.Context,
	idHash [32]byte,
	counter uint64,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	s, ok := m.sessions[idHash]
	if !ok {
		return store.ErrNotFound
	}

	if counter <= s.LastCounter {
		return store.ErrConflict
	}

	s.LastCounter = counter
	m.sessions[idHash] = s
	return nil
}

func (m *MemStore) DeleteSessionsForUser(
	ctx context.Context,
	userID []byte,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for id, s := range m.sessions {
		if bytes.Equal(s.UserID, userID) {
			delete(m.sessions, id)
		}
	}

	return nil
}

func (m *MemStore) DeleteExpired(
	ctx context.Context,
	now time.Time,
) error {
	if err := checkContext(ctx); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	for username, r := range m.reservations {
		if !r.expires.After(now) {
			delete(m.reservations, username)
		}
	}

	for id, until := range m.expiries {
		if !until.After(now) {
			delete(m.expiries, id)
			delete(m.opaque, opaqueKey{userID: id, kind: "password", pending: true})
			for bKey, b := range m.blobs {
				if bKey.userID == id && bKey.kind == store.BlobKindKEK && b.Pending {
					delete(m.blobs, bKey)
				}
			}
		}
	}

	for id, s := range m.loginStates {
		if !s.ExpiresAt.After(now) {
			delete(m.loginStates, id)
		}
	}

	for id, s := range m.sessions {
		if !s.ExpiresAt.After(now) {
			delete(m.sessions, id)
		}
	}

	return nil
}
