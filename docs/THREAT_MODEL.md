# Threat model (draft)

Working name: nanogram (may change). Nothing here is final until listed under "Decided".

## Who we defend against

- A hostile server operator. Can run modified code, log everything, replay, delete, hand out wrong public keys.
- Someone who steals the database or a backup and guesses passwords offline.
- Network attackers.
- Espionage-grade adversaries: seizing a device that is switched off, forcing the operator to hand over data, watching traffic.
- A fake instance or malicious JS pretending to be the real client.
- A device with live malware. We can only limit the damage here, see below.

## What we promise

- The server never sees the password, the keys derived from it, or any plaintext.
- The server cannot log in as a user.
- Guessing the password offline is infeasible (Argon2id plus an enforced strong passphrase).
- Rollback, silent deletion and tampering of stored data get noticed by the client.
- A swapped public key gets noticed if users compare safety numbers.
- Stored chats resist quantum attacks (ML-KEM).
- Changing the password can't lock the user out. The client checks the new blob decrypts before the server drops the old one.
- A seized device that is switched off shows nothing.

## What we don't promise

- Availability. The server can delete everything or go dark. We detect it and allow encrypted exports.
- Live malware on the device. We shorten sessions, lock fast and wipe keys from memory, that's all.
- Metadata. The server sees who talks to whom and when. Padding message sizes and using Tor helps. No fake data.
- Post-quantum protection for the login handshake and for signatures. Stored data uses random 256-bit symmetric keys and ML-KEM. OPAQUE (login) is built on elliptic curves and has no standard post-quantum version yet, as far as we know. Signing keys are Ed25519 for now.
- Forward secrecy in v1. A stolen password exposes history.
- Deletion from old backups or from the other person's copy.

## Clients

CLI and library first. The browser UI comes after, once the protocol is stable.

A browser client only works if its code does not come from the server operator. Otherwise a hostile server ships JS that steals the password. Candidate fix: host the client on a separate, well-known origin (GitHub/GitLab pages) with signed, reproducible builds, and the user enters their server's address. Trust then moves to the maintainers and the host, which we state openly.

## Decided

- Usernames: lowercase ASCII, 3-32 chars.
- Unknown usernames get a fake OPAQUE response.
- Key chain: password key -> KEK -> MEK -> data.
- CLI and library first, browser later.
- Recovery key from v1.
- Offline guessing defence: Argon2id plus a strong passphrase, enforced by the client (generated or checked, weak ones rejected).

## Not yet decided

- Permanent random user ID, username only an alias, ID used as the OPAQUE identifier.
- Identity keypair random and wrapped under the KEK, not derived from the password.
- Secret key as an optional extra for high-security users.
- Second factor: hardware key (WebAuthn PRF) that goes into key derivation. TOTP later.
- Deletion is best effort.
- Go for server and client library, Rust client later, checked against test vectors.
- Where the browser client is served from.
- Epoch keys for forward secrecy, v2.
