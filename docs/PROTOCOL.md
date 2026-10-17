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
- Sessions expire fast. No refresh: when it runs out the client logs in again with the passphrase.
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

### Keys

- export_key: comes out of OPAQUE login or registration, never leaves the client.
- wrap_key = HKDF-SHA-256(export_key, salt empty, info LabelWrap), 32 bytes. Derived on every login, never stored.
- KEK: random 32 bytes, made once at registration. The account key. Everything else is wrapped under it.
- MEK: random 32 bytes, encrypts the user's own stored history. Versioned, so a new one per period can be added later (forward secrecy, v2).
- Identity seeds: random seeds for the ML-KEM key pair and the signing key pair. Only the seeds are stored, the keys are regenerated from them. Public keys are stored in clear.
- recovery_key: random 32 bytes, shown once to the user, never sent. recovery_wrap_key = HKDF-SHA-256(recovery_key, info LabelRecovery).

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

### Password change (not yet decided)

1. User logs in, fetches the kek blob, decrypts KEK with the old wrap_key.
2. Client runs a new OPAQUE registration with the new password, gets a new wrap_key, makes kek blob version n+1.
3. Client decrypts the new blob with the new wrap_key to check it.
4. Server stores the new record and blob as pending, only if the client says it saw version n (compare and swap, stops two devices racing).
5. The client logs in with the new password. Only then the server makes the pending record current. If this never happens within a set time, the old record stays.

Step 5 is what stops a buggy or hostile client from locking the user out with a record for the wrong password.

### Recovery flow

Login with the recovery credential, fetch the recovery blob, decrypt KEK, set a new password as in the password change above (steps 2 to 5).

### Schema changes this needs

- opaque_records: add kind ('password' or 'recovery') and a pending flag, primary key (user_id, kind).
- key_blobs: first version has prev_hash of 32 zero bytes. Use DATETIME in UTC instead of TIMESTAMP. Add ON DELETE CASCADE.
- New table for public keys (user_id, kind, key, version).

### Needs checking

- Go version on every machine: crypto/mlkem needs Go 1.24 or newer.
- Whether ML-KEM keys can be restored from the stored seed with the standard library.
