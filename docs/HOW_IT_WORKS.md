# How nanogram works, in plain language

Also serves as a map of the code.

## The idea in one paragraph

You have a username and a passphrase. The server stores your data but cannot read it, because every piece is locked with keys that only your own device can rebuild from your passphrase. The server also never learns the passphrase, not even while you log in.

## Words used below

- **Password**: whatever the user chooses, as long as the client's strength check accepts it (an estimate of at least 2^66 guesses). A generated passphrase of 7 random words can be suggested.
- **OPAQUE**: the login protocol. It lets you prove you know the passphrase without sending it. A library does the maths.
- **Argon2id**: a deliberately slow, memory-hungry function. It turns the passphrase into key material and makes every password guess expensive. It runs inside the OPAQUE library on the client.
- **export_key**: a secret that comes out of OPAQUE on the client only. The server never gets it.
- **KEK** (key-encryption key): a random master key for the account. It is stored only in encrypted form.
- **MEK**: a random key for your own stored history. It is stored encrypted under the KEK.
- **Blob**: an encrypted package the server stores. There are four kinds: kek, mek, identity, recovery. Each blob is bound to its user, kind and version, so the server cannot swap them around.
- **Recovery phrase**: 24 words. A spare key that can unlock the KEK if you forget the passphrase.
- **Session**: a temporary login. Nothing secret is sent with each request, only a signature.
- **MAC**: a short tag that proves a message came from someone who holds a shared key and was not changed on the way.
- **Scope**: what a session may do. "full" (after a passphrase login) or "recovery" (after a recovery login, only for resetting).
- **Pending**: a login kind, used only to prove the new password of a password change that has begun. A pending login is not a general login.

## Registration

1. Client: turns the passphrase into a blinded request and sends it with the username. (`service.RegisterStart`)
2. Server: checks the username format, makes a random 16 byte user ID, builds its half of the OPAQUE answer, and only then reserves the username for 5 minutes. It returns the user ID and its answer.
3. Client, on its own device: finishes OPAQUE. That gives a **record** (what the server will keep) and the **export_key**. It derives a wrapping key from the export_key, makes a random KEK, MEK and identity seeds, and locks them into blobs. If recovery is on, it also makes the 24 word phrase and a second OPAQUE credential for it.
4. Client sends record, blobs and public keys. (`service.RegisterFinish`)
5. Server: checks the shapes (right kinds, version 1, sizes) and stores everything in one step, but only if the reservation for that name and user ID is still valid.

The server now holds a record (it cannot be turned back into the passphrase), encrypted blobs and public keys. Nothing else.

## Login

1. Client sends the username and its first message. (`service.LoginStart`)
2. Server finds the user and answers with a login ID, the user ID and its OPAQUE reply, and keeps a secret state for 30 seconds. If the username does not exist, it answers with a **fake but consistent** reply of the same shape, so nobody can learn which names exist.
3. Client runs Argon2id (about 2 to 3 seconds on a slow phone) and tries to open the record using the passphrase. A wrong passphrase fails here, on the client. The server learns nothing. A right one gives a proof, a session key and the export_key.
4. Client sends the proof. (`service.LoginFinish`) Server takes the stored state (it can be used exactly once, even if the proof is wrong), checks the proof, and creates the session. It stores only a key derived from the session key, never the raw one.
5. Client fetches its blobs, opens the KEK blob with a key derived from the export_key, then opens the MEK and identity blobs with the KEK.
6. On first contact, the server's public key is shown as a fingerprint and pinned. Every later login compares the key with the pin. A change produces `ErrServerKeyChanged`, not `ErrLoginFailed`; the user runs `ngcli pin` to see both fingerprints and decides.

## Using a session

Every request carries: the session ID, a counter, and a MAC over method, path, counter and a hash of the body. The server (`service.Authenticate`):
1. finds the session (not found or expired: refused),
2. checks the MAC (wrong: refused, and nothing changes),
3. checks the scope,
4. only then requires the counter to be higher than the last one, and in the same step moves the expiry forward.
So a copied request cannot be replayed, changed or sent to another path. This is why sessions use signatures and not a plain token.

A full session slides: every valid request keeps it alive for another 30 minutes, but never longer than 12 hours after the login. A recovery session is fixed at 10 minutes.

## Changing the password

The KEK never changes. Only the blob that holds it is replaced: it is re-wrapped under a key made from the new password, and stored as the next version of the KEK blob, chained to the previous hash. The MEK, the identity and the recovery blob stay as they are.

1. Client: runs a new OPAQUE registration for the new password, with the same user id as the credential id. Gets a new record and a new wrap key. (`service.PasswordChangeStart`)
2. Client: re-wraps the KEK under the new wrap key, checks that it opens again, and sends the record and the new blob together with the version it started from. (`service.PasswordChangeBegin`)
3. Server: stores both as pending for 10 minutes, but only if the current KEK version is what the client said and nothing is already pending (otherwise 409 conflict). Logins still use the old password.
4. Client: proves the new password with a login of kind "pending". The server checks the proof against the pending record. On success it makes both current, ends every older session, and opens a new full session for the client.

If step 4 never happens, the pending change expires and nothing changed. This is what stops a buggy client from locking the user out by setting a record for the wrong password. The device that made the change is not warned about the new KEK version; other devices see a chained newer version and are told, so a silent takeover by someone who knows the old password is noticed.

## Recovery

At registration the client can create a spare key as 24 words. The server stores a second OPAQUE record for it (the recovery credential) and a copy of the KEK locked under it. Logging in with the recovery kind gives a limited "recovery" scope session.

Resetting the password from a recovery session reuses the password change: only the KEK blob is re-wrapped, under a key made from the new password. The same pending mechanism proves the new password and ends every older session. After the change commits, the client rotates the recovery key: a new 24 word phrase, a new OPAQUE credential, and a new recovery blob holding the same KEK. The old phrase stops working. The new phrase is shown once.

A user who has a full session can also disable recovery entirely. After that, a forgotten password means lost data.

## Where the code lives

| Package | What it does | Size |
|---|---|---|
| internal/auth | Wraps the OPAQUE library: server keys file, registration, login start and finish, fake answers for unknown users | ~340 lines |
| internal/zkcrypto | Key derivation labels, blob lock and unlock, hash chain, recovery phrase, request MAC | ~370 lines |
| internal/service | The brain: registration, login, session checks, password change. No network code | ~790 lines |
| internal/store | The storage interface and the in-memory version in memstore | ~1,330 lines |
| client | Registers, logs in, opens the account blobs, checks them against what this device has seen, changes the password. Reads and writes the head file. | ~1,490 lines |
| cmd/ngcli | A developer test client. Not for real accounts. | ~310 lines |
| docs/SCHEMA.sql | The MariaDB tables for a later real store | |

About 5,550 lines of logic and 7,860 lines of tests in total. The part that decides security (auth, zkcrypto, service) is roughly 1,500 lines.

## Rules the code must keep

- The server never sees the passphrase, export_key, KEK, MEK or any plaintext.
- Unknown users, users without recovery, and wrong passphrases look the same from outside.
- Failure shows up on the client only after the slow Argon2id work.
- A login ID works once. A session stores a derived key. The MAC is checked before the counter moves.
- Times are passed in, never read from the clock inside the store.
- Blob associated data binds user, kind, version and the previous hash.
- Identities in OPAQUE: client identity is the user ID (or the recovery credential ID), server identity is nil.
- A password change replaces the KEK blob, not the KEK. Every older session ends, and only after the new password is proven.
- A recovery reset re-wraps the same KEK. Rotation replaces the phrase, not the KEK. The old phrase stops working only after rotation, never before.
- A changed server key is detected before the OPAQUE exchange and reported separately from a login failure.

## Not built yet

The MariaDB store, rate limiting, server key pinning, display names, and everything about messages.
