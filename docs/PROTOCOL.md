# Protocol (draft)

Part 1: registration. Part 2: login. Key wrapping comes after these are agreed.

Based on OPAQUE (RFC 9807) using the Go library github.com/bytemare/opaque. Library version and exact API to be checked against its docs when we start writing code.

## Terms

- Password: the passphrase the user types. Never leaves the client.
- Credential identifier: the permanent user ID (random 128 bit). Not the username.
- Registration record: what the server stores per user. Lets the server run login, tells it nothing about the password.
- export_key: a key only the client can compute after a successful OPAQUE step. Used to derive the key that wraps the KEK.

## Server secrets (not in the database)

- oprf_seed: random bytes, per-user OPRF keys are derived from it plus the user ID.
- AKE keypair: the server's long-term key for the login exchange.

Keep these in a config file or secret store, back them up separately. Losing them locks everyone out. Leaking them lets an attacker run offline guesses against stolen records, so they matter, but they do not reveal chats.

## Settings to fix before coding

- Ciphersuite: ristretto255 with SHA-512 is the library's default family. Not yet decided.
- Key stretching: Argon2id, run on the client. The RFC's example parameters use gigabytes of memory, too much for a browser. We choose our own and write them here. Not yet decided.
- Username rules: lowercase a-z, 0-9, underscore, dot, 3-32 chars. No uppercase. A separate display name (free text, cosmetic) comes later and is never used for identity.

## Registration, two requests

1. Client to server: start
   - username
   - registration_request (the blinded password, from the library)

   Server:
   - rejects a bad or taken username
   - makes a random user_id and reserves the username
   - returns user_id and registration_response

2. Client, locally:
   - finishes OPAQUE with the response, gets registration_record and export_key
   - derives the wrapping key from export_key (HKDF, fixed label, see below)
   - makes the key material (identity keypair, MEK, KEK, recovery key) and wraps it
   - checks it can unwrap what it just wrapped

3. Client to server: finish
   - user_id
   - registration_record
   - wrapped key blobs (format in part 3)

   Server stores everything in one transaction and releases the reservation only if it fails.

## What the server stores per user

- user_id, username, created_at
- registration_record
- wrapped key blobs, each with a version number
- nothing else about the password

## Failure cases to handle

- Two clients race for the same username: the reservation decides, the loser gets an error.
- Client drops after step 1: reservation expires after a short time.
- Replayed finish request: rejected, the user_id is already complete.
- Unknown user at login must look the same as a real one. Needs the fake-record path in the library, checked in part 2.

## HKDF labels (frozen once chosen)

These strings are part of the key derivation. Changing one later makes existing data unreadable.

- storage wrap key: "zkc/v1/wrap"
- recovery wrap key: "zkc/v1/recovery"

The prefix "zkc" is a fixed protocol identifier, not the product name. The product can be renamed freely, the labels never change. Pick the final prefix before the first real user, after that it is frozen. Every label is plain ASCII, versioned ("v1") and defined in one place in the code.

## Part 2: login

Three messages. The library does the OPAQUE maths, we only carry the bytes.

1. Client to server: start
   - username
   - ke1 (credential request, client nonce, client ephemeral key)

   Server:
   - looks up the user and their registration_record
   - if the user does not exist, uses a fake record (library supports this) so the reply looks the same
   - returns login_id and ke2 (credential response, server nonce, server ephemeral key, server MAC)
   - keeps the login state (expected client MAC, session key) under login_id, short lifetime (about 30 s), single use

2. Client, locally:
   - stretches the password with Argon2id, opens the envelope from ke2
   - wrong password, or a server that does not hold the real record, makes this step fail
   - checks the server's long-term public key against the pinned one (see below)
   - produces ke3 (client MAC), session_key and export_key

3. Client to server: finish
   - login_id
   - ke3

   Server checks the MAC. On success it opens a session. On failure it deletes the state and returns the same generic error as an unknown user.

## Server key pinning

First time a client talks to a server it stores the server's public key. After that, a different key is an error the user must confirm by hand. This is how a fake or swapped server gets noticed. For the browser client the key comes from the trusted client origin, not from the server.

## Sessions (decided: per-request MACs)

- On success the server returns a random session_id. It is only a lookup handle, knowing it is not enough to do anything.
- Both sides derive request_key = HKDF(session_key, "zkc/v1/request").
- Every request carries session_id, a counter, and
  MAC = HMAC-SHA256(request_key, method | path | counter | SHA256(body)).
- Server checks the MAC and that the counter is higher than the last one it saw for this session. Replays and reordering fail.
- A full session slides: each valid request extends it to 30 minutes from now, never past 12 hours after the login. A recovery session is fixed at 10 minutes and does not slide. The store applies the cap, in the same step that moves the counter. Requests that fail any check change nothing.
- Responses are not MACed in v1. Tampering by the server itself is covered by the signed, hash-chained data, not by this.

## Login rules

- The server never answers step 1 with an error for an unknown user, no 404, no early exit. It always sends a full-looking ke2. The client only finds out in step 2, after running the full Argon2id stretch, so a wrong password and a missing user cost the same time and look the same. The client must not skip or shorten the stretch on any path.
- One generic error for wrong password, expired state, bad MAC. Same status code, same body, similar timing.
- Rate limit per username and per IP. Counters live in the server, they must not change the reply shape.
- Registration cannot hide whether a username exists. That is accepted.
- login_state storage: memory is fine for one server process. More than one process needs a shared store.

## Library notes (bytemare/opaque, read from pkg.go.dev)

Pin one exact version in go.mod. The API changed between 0.9 and 0.10 (SetKeyMaterial is new in 0.10), so examples found online may not match.

- DefaultConfiguration is ristretto255 + SHA-512 + Argon2id. We take that as the ciphersuite.
- Configuration has a Context field. Set it to a fixed zkc constant. A configuration must never change for existing users.
- Client: RegistrationInit, RegistrationFinalize (returns record and export_key), LoginInit, LoginFinish (returns ke3 and export_key), SessionKey.
- Server: SetKeyMaterial (server identity, secret key, public key, oprf seed), RegistrationResponse (takes the user's credential identifier, our user_id), LoginInit, LoginFinish, SessionKey.
- Fake record: conf.GetFakeRecord(credential id). Build it once, pass it to LoginInit when the user is missing.
- Per-login server state: Server keeps it inside the object. SerializeState and SetAKEState let us store it under login_id between request 1 and 3.
- The server's public key comes back to the client in the registration response, so the client can pin it there.
- Pinning at login: the envelope is bound to the server key chosen at registration, so a different key fails to open it. Confirmed by TestOpaqueMismatchedServerKeys (secret key and OPRF seed cases).
- Pinned versions that work together: bytemare/opaque v0.10.0 with bytemare/ksf v0.4.0. ksf v0.5.0 does not compile with opaque v0.10.0, and its Harden signature differs from v0.4.0. The ksf defaults above were read from a different version than the one in use, so they must be re-checked with the golden test.

## Key stretching in bytemare/ksf (checked)

- Defaults for Argon2id: 3 passes, 64 MiB, 4 threads. This is the second option recommended in RFC 9106.
- The ksf package accepts custom values (time, memory, threads), but opaque.Configuration has no field to pass them. The client calls the stretching function with whatever its internal inputs hold.
- So: either use the defaults (no extra code), or fork or vendor the library to change them. A fork means maintaining crypto code ourselves.
- The defaults are constants in a dependency. If a later release changes them, every user's login breaks. Pin both libraries and keep a golden test (fixed input, fixed expected output) that fails if the result ever changes.

## Still to check

- Whether KE2 for a fake record has the same length as for a real one.
- Where the client reads the server identity and what exactly goes into ServerIdentity.

## Part 3: key wrapping (draft, nothing here is decided yet)

Everything in this part happens on the client. The server only stores the blobs.

Status: password change is decided (two phases, in v1). Recovery is proposed on by default with a skip option. The cipher (XChaCha20-Poly1305 proposed) and the recovery credential (option 1 proposed) are not yet decided.

### Keys

- export_key: comes out of OPAQUE login or registration, never leaves the client.
- wrap_key = HKDF-SHA-256(export_key, salt empty, info LabelWrap), 32 bytes. Derived on every login, never stored.
- KEK: random 32 bytes, made once at registration. The account key. Everything else is wrapped under it.
- MEK: random 32 bytes, encrypts the user's own stored history. Versioned, so a new one per period can be added later (forward secrecy, v2).
- Identity seeds: random seeds for the ML-KEM key pair and the signing key pair. Only the seeds are stored, the keys are regenerated from them. Public keys are stored in clear.
- recovery_key: random 32 bytes, shown once to the user as 24 words from the BIP39 list (proposed, not yet decided), never sent. recovery_wrap_key = HKDF-SHA-256(recovery_key, info LabelRecovery).

### What the server stores (table key_blobs)

- kek blob: KEK under wrap_key
- recovery blob: KEK under recovery_wrap_key
- mek blob: MEK under KEK
- identity blob: identity seeds under KEK

### Blob format

[1 byte format version][24 byte random nonce][ciphertext and tag], using XChaCha20-Poly1305.

The associated data binds a blob to where it belongs:
"zkc/v1/blob" | user_id (16) | kind (1 byte) | version (8 bytes, big endian) | prev_hash (32)

So the server cannot move a blob to another user, another kind or another version without the tag failing.

### Hash chain

hash_n = SHA-256(associated data of blob n | blob n). The first version has prev_hash of 32 zero bytes. The client remembers the newest version and hash it has seen for each kind. If the server later returns an older version or a different hash, the client warns. A brand new device has nothing to compare, so it cannot detect rollback. That limit stays in the threat model.

No signatures here: only someone with the keys can make a valid blob, and the server has none of them. Signatures matter later for public keys and messages.

### Registration, client side

1. Run OPAQUE registration, get the record and export_key.
2. Make KEK, MEK, identity seeds, recovery_key.
3. Build the four blobs, check each one decrypts again.
4. Show the recovery key once, ask the user to confirm they saved it.
5. Send record, blobs, public keys and the recovery credential (below) in the finish request.

### Recovery credential (not yet decided)

Server has to know a lost-password request comes from someone who holds the recovery key, without ever seeing it. Option 1: store a second OPAQUE record whose secret is the recovery key. Reuses code we already test, needs a kind column on opaque_records. Option 2: store a signing public key derived from the recovery key and check a signature on a server nonce. Needs no second OPAQUE state machine but adds a new step. Leaning to option 1.

### Password change (decided for v1)

1. User logs in, fetches the kek blob, decrypts KEK with the old wrap_key.
2. Client runs a new OPAQUE registration with the new password, gets a new wrap_key, makes kek blob version n+1.
3. Client decrypts the new blob with the new wrap_key to check it.
4. Server stores the new record and blob as pending, only if the client says it saw version n (compare and swap, stops two devices racing).
5. The client logs in with the new password. Only then the server makes the pending record current. If this never happens within a set time, the old record stays.

Step 5 is what stops a buggy or hostile client from locking the user out with a record for the wrong password.

### Recovery flow

The recovery key is never used directly. Two independent keys come out of it:
- OPAQUE input for the recovery login: HKDF(recovery_key, info "zkc/v1/recovery-login") (new frozen label, LabelRecoveryLogin)
- recovery_wrap_key: HKDF(recovery_key, info LabelRecovery)

Steps:
1. User enters username and the 24 recovery words (the word list has a built-in checksum, so a typo is told apart from a wrong key).
2. OPAQUE login with the recovery record. The session it opens can only fetch the recovery blob and do a password change, nothing else.
3. Client fetches the recovery blob, decrypts the KEK with recovery_wrap_key.
4. User picks a new passphrase, then the password change above (steps 2 to 5).
5. Client makes a new recovery key, replaces the recovery record and blob, and ends all older sessions. The old recovery key is dead.

### Recovery risks and what limits them

- The recovery key is as good as the account. Anyone holding it can read everything. It must be random 256 bit, shown once, never saved by the app, never sent. The weak spot is where the user keeps it.
- Phishing: a fake page asks for the recovery key. The protocol hides it from the server, but not from malicious page code. The key is only ever asked for on the recovery screen of the trusted client.
- Silent takeover: if the key leaks and someone recovers the account, the kek version goes up. The real user's client sees a version it did not expect and warns. Hiding it needs the server to also rewrite the client's remembered chain head, which it cannot reach.
- Online guessing is pointless against 256 bits, rate limits only protect server load.
- Disabling: a logged-in user can delete the recovery record and blob. Then a lost password means lost data, and the UI says so.
- Typing check at setup: the user is asked to re-enter a few of the words before registration finishes.
- A stolen recovery key also opens all past data. That is the price of recovery without forward secrecy.

### Schema changes this needs

- opaque_records: add kind ('password' or 'recovery') and a pending flag, primary key (user_id, kind).
- key_blobs: first version has prev_hash of 32 zero bytes. Use DATETIME in UTC instead of TIMESTAMP. Add ON DELETE CASCADE.
- New table for public keys (user_id, kind, key, version).

### Needs checking

- Go version on every machine: crypto/mlkem needs Go 1.24 or newer.
- Whether ML-KEM keys can be restored from the stored seed with the standard library.

## Part 4: HTTP API

All bodies are JSON, sent with Content-Type application/json, at most 64 KiB, one value, no unknown fields. Binary fields are standard base64 strings. Every response carries Cache-Control: no-store. Errors are {"error": "<code>"} with these codes: unauthorized (401, used for failed logins and failed signatures alike), invalid_request and invalid_username (400), unsupported_media_type (415), too_large (413), username_taken (409), internal (500).

| Method and path | Body | Answer |
|---|---|---|
| POST /v1/register/start | username, password_request, recovery_request (optional) | user_id, password_response, recovery_response |
| POST /v1/register/finish | user_id, username, password_record, recovery_record (optional), blobs [kind, version, prev_hash (32 bytes), data], public_keys [kind, key] | 204 |
| POST /v1/login/start | username, kind ("password" or "recovery"), ke1 | login_id, user_id, ke2 |
| POST /v1/login/finish | login_id, ke3 | session_id, user_id, scope |
| GET /v1/account/blobs | none, signed, scope full | blobs (kek, mek, identity) |
| GET /v1/recovery/blob | none, signed, scope recovery | blobs (recovery) |

Signed requests carry three headers: X-Session (session id, base64), X-Counter (decimal, must be higher than the last one used) and X-MAC (base64). The MAC is the request MAC from part 2 over the method, the URL path (as the server routes it, without a query string), the counter and the raw body. Requests with a query string on signed routes are refused, because the signature would not cover it.

## Password input

The server never sees the password, and the protocol puts no rule on it: the OPAQUE password is the exact bytes the client sends in. Our clients make one convenience, in the client only: when what the user typed is made entirely of BIP39 words (at least 6), they use the lowercase, single-spaced form, so capitals and spacing do not matter for a generated passphrase. Anything else, for example a password from a password manager, is used exactly as typed. A client that does not do this still works with any account whose password is not a plain word list.

Whether a password is strong enough is judged by the client and only advises: the server cannot see the password and enforces nothing.

Not yet decided: Unicode normalisation (NFC) of non-ASCII passwords, so the same characters typed on different systems give the same bytes. It needs one dependency, golang.org/x/text.

## Decisions of 22 October 2026 (these replace earlier lines)

- Usernames: 3 to 32 characters from a-z, A-Z, 0-9, underscore and dot. Names are matched without regard to case ("Alice" and "alice" are one account) and stored in lowercase. A separate display name can keep capitals later.
- Passwords are chosen by the user. The client refuses a password whose estimated number of guesses is below 2^66, using the zxcvbn estimate with the username as a known word. A generated 7 word passphrase is only a suggestion. The server cannot see or check the password, so this is advice from the client, not a protocol rule.

## Part 5: changing the password

The user is logged in with a full session and holds the KEK. Only the KEK blob is replaced; the KEK, the MEK, the identity and the recovery blob stay as they are.

1. POST /v1/account/password/start (signed, full): password_request, answer password_response. The server answers the OPAQUE registration request with the user id as the credential id, and keeps nothing.
2. The client finishes OPAQUE locally: new record, new export key, new wrap key. It locks the same KEK under the new wrap key as KEK blob version n+1, with the hash of version n as its previous hash, and checks that it opens.
3. POST /v1/account/password/begin (signed, full): expected_version (n), record, kek (the new blob). The server stores both as pending for 10 minutes, but only if the current KEK version is n and no change is already pending (otherwise 409 conflict). Logins still use the old password.
4. The client proves the new password with a login of kind "pending" (login/start and login/finish as usual). The server checks the proof against the pending record. On success it makes the pending record and blob current, ends every older session, and opens a new full session.

If step 4 never happens, the pending change expires and nothing has changed. A device that last saw version n and now sees n+1 with the right previous hash gets a notice, not an error.

## Part 6: recovering a lost password

A recovery session exists so a user who has forgotten the password but kept
the 24 words can set a new one, then replace the phrase. The reset reuses the
password change from part 5; what part 6 adds is the routes through which a
recovery session reaches the KEK header it needs, and a rotation of the
recovery key after the change commits.

### What a recovery session can do

A recovery session (scope "recovery", 10 minutes, no slide, from a login of
kind "recovery") may only:

- read the recovery blob and the current KEK header (GET /v1/recovery/blob),
- start and finish a password change (POST /v1/recovery/password/start and
  /v1/recovery/password/begin).

It may not read the account blobs. It may not do anything else.

A full session may read the same recovery data (GET /v1/account/recovery/blob,
same response shape) so the rotation step does not need a recovery session
after the pending login has ended every older session.

### Flow

1. The user enters the username and the 24 words. The client decodes them
   into the recovery key, derives the login secret, and runs OPAQUE login of
   kind "recovery". The server issues a recovery session.

2. GET /v1/recovery/blob returns the current recovery blob and the current
   KEK blob's version, previous hash and hash. The client opens the recovery
   blob with the recovery wrap key to obtain the KEK.

3. POST /v1/recovery/password/start asks the server for its OPAQUE half of
   the new password. Credential id is the user id, as in part 5.

4. The client finishes OPAQUE locally, locks the same KEK under the new wrap
   key as KEK blob version n+1, chained to the KEK hash from step 2, and
   checks the blob opens.

5. POST /v1/recovery/password/begin stages the change as pending for 10
   minutes, with the same rules as part 5, step 3.

6. The client proves the new password with a login of kind "pending". On
   success the change is committed, every older session ends, and a full
   session is issued.

7. The client, now on the new full session, reads the current recovery blob
   with GET /v1/account/recovery/blob to learn the version and hash the
   rotation chains onto.

8. POST /v1/account/recovery/rotate/start returns the OPAQUE registration
   response for a new recovery credential (credential id is
   RecoveryCredentialID(user id)).

9. The client makes a new 32 byte recovery key, derives the new login secret
   and the new recovery wrap key, finishes OPAQUE locally, locks the same
   KEK under the new wrap key as recovery blob version n+1 chained to the
   hash from step 7, and checks the blob opens.

10. POST /v1/account/recovery/rotate/begin sends the new record, the new
    blob, and the recovery version the client started from. The server
    checks the current recovery version is what the client said (409
    conflict otherwise) and replaces record and blob atomically.

11. The client shows the new 24 words once.

### Disabling recovery

POST /v1/account/recovery/disable removes the recovery record and every
recovery blob, and ends any recovery session. It is idempotent: 204 whether
or not recovery was set up.

Re-enabling recovery (a new registration of a recovery credential via
rotate/start and rotate/begin with expected_version 0) restarts at blob
version 1. The client does not track recovery heads, so there is no false
rollback error. The recovery blob holds the KEK, which does not change
across recovery versions, so a rolled-back recovery blob can only give the
same KEK, and a rotated one fails to open. There is therefore nothing for
a recovery head to detect.

### Routes

| Method and path | Scope | Body | Answer |
|---|---|---|---|
| GET /v1/recovery/blob | recovery | none | blobs [recovery], kek_header {version, prev_hash, hash} |
| POST /v1/recovery/password/start | recovery | password_request | password_response |
| POST /v1/recovery/password/begin | recovery | expected_version, record, kek | 204 |
| GET /v1/account/recovery/blob | full | none | blobs [recovery], kek_header {version, prev_hash, hash} |
| POST /v1/account/recovery/rotate/start | full | recovery_request | recovery_response |
| POST /v1/account/recovery/rotate/begin | full | expected_version, recovery_record, recovery_blob | 204 |
| POST /v1/account/recovery/disable | full | none | 204 |

All are signed. All refuse a query string. All use the request MAC from
part 2.

### Failure cases

- If rotation never runs, the old phrase still works. The user must rotate
  to replace it; the password reset itself is complete.
- If step 6 fails because the pending change expires before the new password
  is proven, nothing changed. The user starts over at step 3.
- If step 10 fails after step 6 succeeded, the password is new and the
  phrase is old. Both still work; the client reports it and offers to retry
  rotation.
- A concurrent password change or recovery reset on another device is
  serialised by the pending flag: only one can be pending at a time. Trying
  to start a second gives 409 conflict.
- A recovery session that tries to read the account blobs, or a full session
  that tries POST /v1/recovery/password/*, is refused with 401.
- Reading /v1/account/recovery/blob or rotating when recovery is not set up
  gives 404 with error code "recovery_not_set_up".

### Store changes

- ReplaceRecovery gains an expectedVersion argument, so a rotation from an
  out-of-date version gives ErrConflict. Nothing else in the store changes.
- DeleteRecovery is used unchanged.
- The pending mechanism from part 5 is reused as-is.

## Part 7: abuse protection

This part covers mechanisms that bound the cost of abusive volume against
the two unauthenticated endpoints (`POST /v1/register/start` and
`POST /v1/login/start`). It exists because on an onion service the server
cannot see a client's address, and any mechanism that pretends otherwise
is a lie in the source.

### What this part promises

- A legitimate user can almost always register and log in.
- A spammer who finds one name cannot hold it for long.
- A hostile or compromised server cannot force a client to burn more than
  2 × 2^cap Blake2b hashes per login or registration attempt, where cap is
  the client's locally chosen maximum difficulty. The client refuses a
  solve above its cap, and it refuses to retry after a second
  `pow_invalid` for the same operation.
- Server-side enforcement of the proof of work is authoritative and cannot
  be bypassed by a modified client. The client-side cap protects the user
  from a hostile server, not the server from a hostile client.
- A passive observer of the wire learns nothing new from these mechanisms.

### What this part does not promise

- Availability. A funded attacker who can generate sufficient volume can
  still degrade service. This is already true of the threat model
  (docs/THREAT_MODEL.md, "What we don't promise") and is restated here so
  that a reader of this part does not infer a guarantee.
- Identification. None of these mechanisms identifies a user, and none
  may be extended to do so without changing the threat model.

### What a modified client can and cannot do

The server independently verifies every proof-of-work solution against its
own state: the MAC recomputes, the difficulty matches the server's current
`f(n)`, the hash has the required trailing zero bits, the nonce is not in
the replay cache. The client's local cap has no bearing on what the server
accepts.

A modified client can therefore:

- refuse to solve a challenge it dislikes, and thereby deny its own user
  access;
- send an insufficient solution, which the server rejects with
  `pow_invalid`;
- return different values to its user than it received, which is the
  broader "live malware" scenario the threat model already classifies as
  limited defence only.

A modified client cannot:

- make the server accept a solution below the difficulty the server
  requires;
- make the server accept a reused nonce;
- make the server skip the verification altogether.

The abuse mechanism's scope is that a standard client cannot bypass it.
A modified client is a modified client; it is the modified client's user
who pays. This is a general property, not specific to proof of work.

### Tor introduction proof of work (operational, not protocol)

The server operator MUST enable Tor's onion-service proof of work
(`HiddenServicePoWDefensesEnabled 1` in `torrc`, with
`HiddenServicePoWQueueRate` and `HiddenServicePoWQueueBurst` sized to the
server's capacity). This is an operational setting, not part of the
protocol, and its correctness is not something the protocol verifies. It
raises the cost of reaching the service during periods of overload. It
does not bound what a reachable client can ask the service to do; that is
what the rest of this part is for.

### Mechanisms

#### 1. Token buckets, keyed on identities, never addresses

The server maintains token buckets that limit request rate. Every request
is checked against one or more of these buckets, and refused with 429 and
`busy` if any of them is empty:

- `anon_new:global` — every unauthenticated request (`register/start`,
  `login/start`, `pow/challenge`). This is what catches an attacker who
  rotates usernames: each fresh name has a fresh `user:` bucket, but
  `anon_new:global` does not care which name is being tried.
- `user:<HMAC(server_secret, canonical username)>` — every request that
  names a username. Refused when the named bucket is empty. This catches
  an attacker who concentrates on one name.
- `session:<sha256(session_id)>` — every signed request. Signed requests
  are not checked against `anon_new:global`.

The server MUST NOT use `RemoteAddr`, `X-Forwarded-For`, or any other
network-level identifier as a bucket key. Reason: on an onion service
every request arrives from the Tor daemon on loopback; the key would be
identical for all clients.

The server MUST hash usernames before using them as bucket keys. Reason:
the bucket state would otherwise be a plaintext list of probed names,
which is metadata the server does not otherwise collect.

Bucket sizes are operational and not part of the wire. Starting points,
reviewable as the operator learns the load: `anon_new:global` at 10
requests per minute per source process, `user:*` at 5 per minute per
name, `session:*` at 60 per minute per session. A legitimate onboarding
costs at most 2 requests to `register/start` and one to `login/start`.

#### 2. Per-username caps on outstanding state

The server bounds, per hashed username:

- outstanding login states at 3 (30-second lifetime each, already in
  part 2);
- outstanding username reservations at 1 (5-minute lifetime, already in
  part 1).

A request that would exceed either cap is refused with 429 and the error
code `busy`. This is different from a per-request rate limit because it
costs the attacker a slot for the whole lifetime of the state, not just
one request.

#### 3. Stateless proof of work on `register/start` and `login/start`

Both unauthenticated endpoints require a proof-of-work solution, bound to
the request. The scheme:

- **Challenge.** The server issues `{nonce, difficulty, issued_at, mac}`
  via `POST /v1/pow/challenge`, body
  `{"purpose": "register"|"login", "username": "..."}`. `nonce` is 16
  random bytes; `issued_at` is Unix seconds; `difficulty` is a number of
  trailing zero bits; `mac` is
  `HMAC-SHA-256(pow_secret, "zkc/v1/pow" | nonce | difficulty | issued_at | purpose | username)`.
  A new `pow_secret` is generated at server start; challenges do not
  survive a restart.
- The first-contact challenge fetch is unauthenticated: a man-in-the-middle
can serve a challenge at any difficulty. The client's local cap is the
defence. The client pays one bounded solve (at most 2^cap hashes), the
server rejects the resulting solution because it does not match a
challenge the server issued, and the client sees `pow_invalid`. This is
an accepted cost of one bounded solve per MITM attempt; it does not
compromise any secret, because the password does not leave the client
until OPAQUE `LoginFinish`, and the OPAQUE exchange is bound to the
server's long-term public key (part 2, "Server key pinning").

- **Solution.** The client searches `solution_counter` (uint64) until
  `Blake2b-256("zkc/v1/pow-solve" | nonce | difficulty | solution_counter)`
  has `difficulty` trailing zero bits, then includes
  `{"nonce", "issued_at", "solution_counter"}` in the original request
  (as `register/start`'s or `login/start`'s `pow` field).

- **Verification.** The server MUST accept the solution only if all of:
  - the recomputed MAC equals the received one (the challenge is one the
    server issued, with the difficulty, issued_at, purpose and username
    it chose);
  - `issued_at` is within 60 seconds of the server clock;
  - `difficulty >= f(current_failure_count(username))`, where `f` is
    defined in mechanism 4 below and `current_failure_count` is the
    server's count at verify time;
  - the solution is valid for `(nonce, difficulty, solution_counter)`;
  - `nonce` is not in the replay cache.

- **Replay cache.** A bounded LRU of `(nonce)` values, sized to
  `max_solve_rate * 60s * safety_margin`. Starting point: 20,000 entries.
  On accept, the nonce is inserted. On eviction, the oldest is dropped;
  a nonce evicted after its 60-second window is already unusable because
  the window check rejects it. The replay window is therefore bounded by
  the cache size and the 60-second validity, not by unbounded storage.
  This is the honest bound: replay within the window is possible if the
  attacker can exceed the cache, which requires solving at the current
  difficulty for each entry, which is exactly the cost the PoW is meant
  to impose.

- **Difficulty function.** `f(n) = min(base + n, server_cap)` where
  `base = 15`, `step = 1`, `server_cap = 20` (in bits). `n` is the number
  of failed login attempts for this username in the last 15 minutes
  (mechanism 4). For `register/start`, `n = 0`.

- **Client-side cap.** The client MUST refuse to solve a challenge whose
  `difficulty` exceeds its local maximum, `max_client_cap = 22` (about
  four seconds of Blake2b on a slow phone). Refusal is a local error,
  never a wait. Reason: a hostile server cannot force a client to burn
  CPU by sending an arbitrarily large difficulty. The two-bit headroom
  between `server_cap` and `max_client_cap` is deliberate: it allows the
  server to raise `server_cap` under sustained load without breaking
  honest clients, while still bounding what a hostile server can make an
  honest client do to four seconds of CPU per solve.

- **Error shape.** A missing, stale, or wrong PoW gives 428 Precondition
  Required with `{"error":"pow_invalid"}`. This MUST be the same shape
  whether the failure was a missing solution, a stale `issued_at`, an
  insufficient `difficulty`, an already-used `nonce`, or a bad MAC.
  Reason: an attacker inspecting the source knows all the failure modes;
  the response must not tell them which they hit.

#### 4. Escalating login difficulty, no lockout

The server keeps, per hashed username, a bounded sliding window of the
last 32 `login/start` timestamps within the last 15 minutes, regardless
of whether the client went on to send `login/finish`. This count drives
mechanism 3's difficulty for the next `login/start` on that name.

Counting `login/start` and not `login/finish` matters: an attacker with
an OPAQUE client fails on the client side (wrong password = OPAQUE
client `LoginFinish` fails) and never sends `login/finish`, so counting
`login/finish` failures would miss the main brute-force pattern and
let an attacker iterate passwords at the base difficulty forever.

On a successful `login/finish`, the count is cleared after the response
is built (so `recent_failures` reflects what the user is being told
about, not the post-clear zero).

The server MUST NOT refuse a login because of past failed attempts, with
any error code, at any point, for any length of time. Reason: a strong
password makes online guessing hopeless and a refusal lets any attacker
who knows a username lock out its owner.

The `login/finish` response MUST include `recent_failures`:
`{"count": <int>, "first": <unix seconds>, "last": <unix seconds>}`. The
client MUST show this to the user after a successful login. Reason: this
is how a user learns their name has been targeted; it does not require
the server to hold contact details or send a message outside the
connection.

The count in `recent_failures` reflects the attempts recorded for this
username since the previous successful `login/finish`, *before* the
current attempt's success clears it. The clear happens after the
response body is built, not before.

The server MUST NOT attempt to notify a user of failed attempts through
email, SMS, push notifications, or any other channel. Reason: the server
is untrusted, the client's device is the only channel it controls, and
adding a contact channel is a metadata store with no security benefit.

### Wire changes

| Endpoint | Method | Body | Answer |
|---|---|---|---|
| POST /v1/pow/challenge | POST | purpose, username | nonce, difficulty, issued_at, mac |
| POST /v1/register/start | POST | username, password_request, recovery_request (optional), pow | (unchanged) |
| POST /v1/login/start | POST | username, kind, ke1, pow | (unchanged) |
| POST /v1/login/finish | POST | login_id, ke3 | session_id, user_id, scope, recent_failures |

`pow` is `{"nonce": base64, "difficulty": uint8, "issued_at": int64,
"mac": base64, "solution_counter": uint64}`.

`recent_failures` is `{"count": int, "first": int64, "last": int64}`, all
zero when there are none.

New error codes: `pow_invalid` (428), `busy` (429).

`POST /v1/pow/challenge` is unauthenticated and is charged to the global
bucket only. The per-username bucket is charged by `register/start` and
`login/start`, once per request: a legitimate login costs one user token,
not two, so "five per minute per name" means five logins per minute, not
two and a half. A client that spams challenge requests drains its own
`anon_new:global` allowance without starving its own user bucket.

Signed routes do not require PoW. Their rate limit is mechanism 1's
session bucket; their identity is the session MAC.

### Failure cases

- If the client receives `pow_invalid`, it MUST fetch a fresh challenge
  and retry exactly once. A second `pow_invalid` in a row is a protocol
  error and MUST NOT be retried. This is what bounds the per-operation
  cost to 2 × 2^cap hashes (see "What this part promises"); a client
  that retries more than once violates the bound.
- If the client receives `busy`, it MUST NOT retry automatically. The
  user is told and chooses to try later.
- If the client receives a `difficulty` above its cap, it MUST refuse.
  The user is told. The server cannot be trusted to accept that choice
  anyway.
- If the server restarts, all challenges in flight are invalid (the
  secret is regenerated) and clients see `pow_invalid`; they fetch a
  fresh challenge and retry.
- The server MUST NOT clear the attempt count for a username except on
  a successful `login/finish` for that username, or after expiry of the
  entries in the sliding window.

### What an attacker who has read this can do

- They can drain the `anon_new:global` bucket and reduce onboarding rate
  for others. This is a known griefing trade-off; the PoW absorbs the
  excess at a cost to the attacker, and the bucket recovers within a
  minute.
- They can pollute a specific user's failed-attempt count by attempting
  failed logins, raising that user's PoW difficulty. The user is never
  refused; the user pays a bounded extra cost (at most `2^cap` hashes,
  about a second) until they succeed, and then it clears.
- They can precompute challenges for one username and try guesses in
  bulk, but each guess costs the current difficulty, which rises with
  each failure they cause, and prefetched challenges become invalid once
  the count rises above their `issued_at` difficulty. The amortised
  strategy therefore fails.
- They can identify a username's `recent_failures` count by observing
  the difficulty of the challenges issued for it. This is already
  inferable (they are the ones causing failures), and the spec accepts
  it: no additional metadata is exposed.

### What this does not solve

- Sustained-load griefing at the Tor introduction layer. Tor's PoW
  reduces it, does not prevent it.
- Availability. If the attacker's budget exceeds the operator's, the
  service is degraded or unreachable.
- Name squatting by an attacker willing to solve the PoW on many names.
  The PoW raises the cost; the reservation lifetime bounds the
  individual hold; a determined attacker holds as many names as they
  can solve for.

### Storage

- Token buckets and replay cache: ephemeral, in memory, per server
  process. A multi-process deployment must either route by session (so
  buckets are local) or use a shared store; this is a MariaDB-store
  problem, not a protocol one.
- `pow_secret`: also per server process by default. A multi-process
  deployment must either (a) load-balance so that a challenge fetch and
  the request that carries its solution go to the same process, or
  (b) share one `pow_secret` across processes at start. The
  single-process `cmd/server` uses (a) trivially. The spec does not
  mandate which; the deployment does.
- Failed-attempt counters: bounded ring buffer per username, in memory,
  cleared on success and on expiry. A persistent store may keep them for
  visibility, but their absence on restart is a documented, bounded loss
  (an attacker who waits for a restart resets their own escalation).
