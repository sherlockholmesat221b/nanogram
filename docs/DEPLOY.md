# Deploying a nanogram server

The server binds loopback. Put it behind Tor or a TLS reverse proxy. Back
up the key file. Publish the fingerprint.

## 1. Build and generate keys

    go build -o bin/server ./cmd/server
    bin/server -init-keys -keys server-keys.json

`server-keys.json` contains the OPAQUE private key, public key and OPRF
seed. It is created with mode 0600 and never overwritten. Back it up now.

If you lose it, every user is locked out. If it leaks, an attacker can run
offline guesses against stolen records (not decryption: chats use separate
keys). Back up by copying the file to an encrypted medium. Never put it in
a public repository.

## 2. Run the server

    bin/server -addr 127.0.0.1:8080 -keys /path/to/server-keys.json

Plain HTTP on loopback. Bind to `127.0.0.1` and expose it through Tor or a
TLS reverse proxy; do not bind to `0.0.0.0`.

## 3. Tor onion service

`/etc/tor/torrc`:

    HiddenServiceDir /var/lib/tor/nanogram/
    HiddenServicePort 80 127.0.0.1:8080
    HiddenServicePoWDefensesEnabled 1
    HiddenServicePoWQueueRate 250
    HiddenServicePoWQueueBurst 2500

The proof-of-work lines are required by Part 7 of the protocol. They make
the service shed circuits under load. Leave the queue rate and burst at
these values until you have a reason to change them; they scale with
server capacity, not with user count.

After `systemctl reload tor`, `/var/lib/tor/nanogram/hostname` holds the
`.onion` address. Distribute that address to your users.

The server's OPAQUE public key fingerprint is *not* the onion address.
Publish both, separately, on a channel your users can verify.

## 4. TLS reverse proxy

If you prefer TLS, run nginx or Caddy on the host and proxy to
`127.0.0.1:8080`. Caddy is the smaller configuration:

    nanogram.example.com {
        reverse_proxy 127.0.0.1:8080
    }

Ensure the proxy does not strip `X-Session`, `X-Counter` or `X-MAC`.
Ensure it does not rewrite paths: the API paths are signed as they appear.

## 5. systemd unit

`/etc/systemd/system/nanogram.service`:

    [Unit]
    Description=nanogram server
    After=network.target

    [Service]
    User=nanogram
    Group=nanogram
    StateDirectory=nanogram
    WorkingDirectory=/var/lib/nanogram
    ExecStart=/usr/local/bin/server -addr 127.0.0.1:8080 -keys /var/lib/nanogram/server-keys.json
    Restart=on-failure
    RestartSec=5s
    NoNewPrivileges=yes
    ProtectSystem=strict
    ProtectHome=yes
    PrivateTmp=yes
    PrivateDevices=yes

    [Install]
    WantedBy=multi-user.target

The key file must be readable by the `nanogram` user and no one else.
`StateDirectory=nanogram` creates `/var/lib/nanogram` with the right
permissions on first start.

## 6. Publish your fingerprint

Compute:

    sha256sum server-keys.json  # not this one
    cat server-keys.json | jq -r '.public_key' | base64 -d | sha256sum

The fingerprint a client shows is `SHA256:` followed by the raw base64 of
the SHA-256 of the *OPAQUE public key* (the `public_key` field in the key
file). Get it with:

    bin/ngcli pin -server https://nanogram.example.com

which prints:

    Not pinned. Server presents: SHA256:AbCdEf...

Publish that string, together with your service address, on a channel
your users trust:

- the GitLab README (if the operator of the server is the maintainer of
  the repo),
- a GPG-signed release announcement,
- a printed card handed to users in person (the strongest channel).

Users compare it with the fingerprint `ngcli` prints on first contact and
then run `ngcli pin -server ... --accept`. After that, any change to the
server's key is refused until the user explicitly re-pins.

Do not publish the fingerprint on the server itself. A fake server can
serve a fake fingerprint as easily as a fake key.

## 7. Logging and what not to log

The server logs internal errors with a timestamp. It does not log request
bodies, usernames, session IDs, or MACs. If you add logging, follow that
rule.

Logs that identify who contacted the server undermine the anonymity the
whole design is built around.

## 8. Backups and updates

Back up `server-keys.json` and the MariaDB database (once the SQL store
lands). Losing the key file locks out every user. Losing the database
loses every account, but not the clients' local data.

To update the server, replace the binary and restart. Existing sessions
survive (the session MAC keys are in the database, not the binary);
existing login challenges do not (the PoW secret regenerates at start, as
Part 7 requires). Clients handle the challenge regeneration automatically.

## 9. Signing the OPAQUE public key with the onion service key

When serving on a `.onion` address, configure the server to sign its
OPAQUE public key with the onion service key. The `.onion` address itself
commits to the onion public key, so a client that verifies the signature
knows it is talking to the service that owns the address. This closes the
first-contact window without requiring the user to compare fingerprints.

The onion service key is `hs_ed25519_secret_key` in the hidden service
directory. It belongs to the Tor user, not to the nanogram user. Copy it
to a path the nanogram user can read:

    sudo cp /var/lib/tor/nanogram/hs_ed25519_secret_key /var/lib/nanogram/onion_key
    sudo chown nanogram:nanogram /var/lib/nanogram/onion_key
    sudo chmod 0600 /var/lib/nanogram/onion_key

Start the server with the flag:

    bin/server -addr 127.0.0.1:8080 \
        -keys /var/lib/nanogram/server-keys.json \
        -onion-key /var/lib/nanogram/onion_key

Re-copy the file if the hidden service is regenerated.

When mode 2 is configured:

- The client verifies the signature automatically and refuses a mismatch
  (`ErrServerKeyChanged`) before the OPAQUE exchange.
- The client does not prompt the user to compare fingerprints on first
  contact, because the address already commits to the key.
- The user can still pin the OPAQUE key. The pin catches a later rotation
  of the OPAQUE key on the same onion service, which the onion signature
  alone cannot.

When mode 2 is not configured, `.onion` clients fall back to mode 1 and
print a warning. Both modes protect against different attacks; mode 2 is
the stronger default for `.onion` and you should enable it if possible.
