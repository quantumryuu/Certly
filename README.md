# Certly: a small private CA for homelab mTLS

Certly is a self-hosted web app for running your own certificate authority. It issues the certificates mutual TLS (mTLS) needs, exports them in every common format, and handles revocation, including revocation on a date you set. It ships as **one static Go binary** that runs on a plain Linux VM or in Docker.

- **CA hierarchy:** root CAs and intermediate CAs, with path length limits
- **Certificates:** client (`clientAuth`), server (`serverAuth`, with DNS/IP SANs), or both. Key types are ECDSA P-256 (default), P-384, RSA 2048/3072/4096 and Ed25519. You can also **sign a CSR** so the key never leaves the device.
- **Export formats:**
  - PEM: cert, chain or fullchain
  - DER
  - **PKCS#12** (`.p12`) with AES-256
  - **encrypted PKCS#8** keys
  - a **zip bundle** with everything plus a README
- **Revocation:** revoke **now** or **at a date and time**, with an RFC 5280 reason code. You can cancel a scheduled revocation before it happens.
- **CRLs:** each CA publishes a CRL at a public URL, as DER or PEM, ready for nginx and HAProxy. Optionally, the URL is embedded in every certificate the CA issues (`CERTLY_BASE_URL`).
- **Expiry dashboard and renewal:** see what expires in the next 30 days, and renew with one click (the form is pre-filled).
- **Import:** bring in the CAs and certificates your old scripts made, including encrypted keys.
- **Security:**
  - private keys are encrypted at rest with a master key (AES-256-GCM)
  - a single admin account with argon2id password hashing, optional **TOTP** two-factor, and brute-force lockout
  - CSRF protection, a strict CSP, and a full **audit log**
- **Backup and restore:** a consistent snapshot while the app is running. Backups can be encrypted with [age](https://age-encryption.org), and nightly backups with retention are available through a systemd timer.

> **Status: early but working (v0.x).** Every feature above is implemented and tested, including a real mTLS handshake that is rejected after revocation. Expect rough edges and don't expose Certly to the internet. Please report security issues privately, as described in [SECURITY.md](SECURITY.md).

---

## Contents

- [Quick start: Docker](#quick-start-docker)
- [Quick start: bare Linux with systemd](#quick-start-bare-linux-with-systemd)
- [Configuration](#configuration)
- [First run](#first-run)
- [Day-to-day use](#day-to-day-use)
- [Using the certificates for mTLS](#using-the-certificates-for-mtls)
- [Backup and restore](#backup-and-restore)
- [Running behind a reverse proxy](#running-behind-a-reverse-proxy)
- [Command-line reference](#command-line-reference)
- [Security model](#security-model)
- [Upgrading](#upgrading)
- [Development](#development)

---

## Quick start: Docker

```sh
git clone https://github.com/quantumryuu/Certly.git && cd Certly
docker compose up -d
docker compose logs certly     # shows where the master key was created
```

Open `http://<host>:8080` and create the admin account.

- Everything is stored in the `certly-data` volume at `/data`: the database, the master key and the lock file.
- The container runs as uid 65532 on a read-only root filesystem, with all Linux capabilities dropped.
- Images are published to `ghcr.io/quantumryuu/certly` for `linux/amd64` and `linux/arm64`. The compose file can also build the image locally.

**Back up the master key now:**
```sh
docker compose cp certly:/data/master.key ./certly-master.key   # store it in your password manager, then delete this copy
```

## Quick start: bare Linux with systemd

```sh
# 1. Download the release for your architecture, check it, install it
#    (from https://github.com/quantumryuu/Certly/releases)
sha256sum -c checksums.txt --ignore-missing
tar xzf certly_*_linux_amd64.tar.gz
sudo install -m 0755 certly /usr/local/bin/certly

# 2. Service user and private data directory
sudo useradd --system --home /var/lib/certly --shell /usr/sbin/nologin certly
sudo install -d -o certly -g certly -m 0700 /var/lib/certly

# 3. Configuration
sudo install -d -m 0755 /etc/certly
sudo install -m 0600 deploy/certly.env.example /etc/certly/certly.env
sudoedit /etc/certly/certly.env            # listen address, TLS, optional base URL

# 4. Service (with systemd sandboxing) and the nightly backup timer
sudo cp deploy/certly.service deploy/certly-backup.service deploy/certly-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now certly certly-backup.timer
journalctl -u certly -n 20                 # shows where the master key was created
```

To build from source instead, run `CGO_ENABLED=0 go build -o certly ./cmd/certly`. It needs Go 1.27 or newer.

## Configuration

Settings come from environment variables. Each variable also has a matching flag, and a flag overrides its variable. Run `certly serve -h` to see the flags.

| Variable | Default | Description |
|---|---|---|
| `CERTLY_BASE_URL` | *(empty)* | **Optional.** When set, every certificate embeds `<base>/crl/<ca-id>.crl` as its CRL distribution point, for clients that fetch CRLs themselves (Windows, some Java apps and appliances). Leave it empty if your servers load the CRL from a file (nginx `ssl_crl`, HAProxy `crl-file`). Then certificates carry no CRL address, and the CA page shows the CRL URLs anyway. The address is baked into each certificate when it's issued, so **decide before issuing**. If it starts with `https://`, secure cookies switch on automatically. |
| `CERTLY_SECURE_COOKIES` | `auto` | `auto`, `true` or `false`. When on, cookies are marked `Secure` (`__Host-` prefix) and HSTS is sent. `auto` turns it on when `CERTLY_TLS_CERT` is set or `CERTLY_BASE_URL` starts with `https://`. **Set `true` behind a TLS reverse proxy** if you don't set a base URL. |
| `CERTLY_LISTEN` | `:8080` | Address and port to listen on |
| `CERTLY_DATA_DIR` | `/var/lib/certly` (Docker: `/data`) | Where the database, master key and lock file live. Must be private (`0700`). |
| `CERTLY_MASTER_KEY_FILE` | `$CERTLY_DATA_DIR/master.key` | The 32-byte master key, base64-encoded. It's generated on the first `serve` if missing. Certly refuses to start if the file is readable by group or others. |
| `CERTLY_TLS_CERT` / `CERTLY_TLS_KEY` | *(empty)* | Serve HTTPS directly (TLS 1.2 or newer). Leave empty when running behind a reverse proxy. |
| `CERTLY_ALLOWED_ORIGINS` | *(empty)* | Comma-separated browser origins to trust for form submissions, e.g. `http://192.168.1.10:8080,https://certly.lan`. You only need it if you get **"Request blocked" / "Origin does not match Host"**, which happens when a proxy or port forward changes the `Host` header. `CERTLY_BASE_URL` is trusted automatically. |
| `CERTLY_TRUSTED_PROXIES` | *(empty)* | Comma-separated CIDRs of reverse proxies whose `X-Forwarded-For` and `X-Forwarded-Host` headers are trusted. This is needed for correct client IPs in the audit log, for per-IP login lockout, and for proxies that rewrite `Host`. |
| `CERTLY_CRL_VALIDITY` | `168h` | How long each CRL is valid (between 1h and 90 days). CRLs are re-signed at half this time, and immediately whenever a certificate is revoked. |
| `CERTLY_LOG_FORMAT` | `text` | `text` or `json` |
| `CERTLY_LOG_LEVEL` | `info` | `debug`, `info`, `warn` or `error` |
| `CERTLY_BACKUP_PASSPHRASE` | *(empty)* | Used by `certly backup -encrypt` and `certly restore` instead of prompting. Meant for the systemd timer. |

## First run

1. **Create the admin.** Open the UI, which sends you to `/setup` the first time. That page works only while no account exists. On a headless host you can run `certly admin create` instead, which prompts for the password, or reads it from stdin if stdin isn't a terminal.
2. **Back up the master key**, separately from your backups (see [Backup and restore](#backup-and-restore)).
3. **Turn on two-factor:** go to **Settings → Two-factor authentication** and scan the QR code.
4. **Create a root CA** under **CAs → New root CA**. The defaults are a 10-year validity and path length 1. The root's only job is to sign intermediates.
5. **Create an intermediate CA**: open the root and click **New intermediate**. A 3–5 year validity with path length 0 works well. Issue every certificate from the intermediate.
6. **Issue certificates**: a **server** certificate for each service (with its DNS names or IPs), and a **client** certificate for each user or device.

Already have CAs from scripts? Use **Import** instead of steps 4–5. Import **roots first, then intermediates, then leaf certificates.**

## Day-to-day use

### Issuing

Go to **Certificates → New certificate** and choose:
- the type (client, server, or both)
- the issuing CA
- the subject
- the SANs: DNS names, IPs, emails, URIs (e.g. `spiffe://…`)
- the key type and validity

Server certificates need at least one DNS name or IP. A certificate can't outlive its issuer, and **revoked or expired CAs, including any CA higher up the chain, can't issue.**

**Signing a CSR:** expand *Sign a CSR instead* and paste or upload the CSR. The key stays on the device. Only the CSR's public key is used: the subject and SANs come from the form, so a CSR can't sneak in extra names or extensions. No private key is stored, so the key-based exports aren't offered for that certificate.

### Exporting

Open a certificate, pick a format under **Download**, and set a password if the format needs one.

| Format | Contents | Typical use |
|---|---|---|
| Certificate (PEM) | the certificate | anything |
| Certificate (DER) | the certificate, binary | Java, Windows, appliances |
| CA chain (PEM) | intermediate(s) + root | `ssl_client_certificate`, trust stores |
| Full chain (PEM) | certificate + chain | nginx `ssl_certificate`, HAProxy, Traefik |
| Private key (PKCS#8 PEM) | the key, **encrypted with AES-256 if a password is set** | servers, curl |
| PKCS#12 (`.p12`) | cert + key + chain, **password required** | browsers, macOS/iOS/Android, Windows |
| Zip bundle | cert, chain, fullchain, root CA, `README.txt`, and optionally the key (encrypted if a password is set) plus a `.p12` | handing one device everything it needs |

The rules:
- Passwords must be at least 8 characters. **Use a long random password** for anything that leaves your network, e.g. `openssl rand -base64 18`.
- **CA private keys can only be exported encrypted.**
- PKCS#12 and encrypted keys use PBKDF2-HMAC-SHA256 with 600,000 iterations and AES-256-CBC. They open with OpenSSL 1.1.1+, Windows 10 1809+/Server 2019+, macOS, iOS and Android. Very old devices that need 3DES/RC2 PKCS#12 aren't supported, deliberately.
- Zip files themselves are not password-protected, because zip encryption is weak. The key and `.p12` inside are what get encrypted.
- Every export is recorded in the audit log, including whether a key was included.

### Revoking

Open the certificate, go to **Revoke**, and choose:
- **Now**: the CRL is re-signed straight away.
- **At a date and time (UTC)**: a background job checks every minute and revokes the certificate at that time. You can **cancel** before then.

Then pick a reason (key compromise, superseded, …) and tick the confirmation box.

### Renewing

Click **Renew** on a certificate, or next to it on the dashboard's *Expiring within 30 days* list. You get the issue form pre-filled with the same subject, SANs, key type, validity and issuer. A new key and serial are generated. Once the new certificate is deployed, revoke the old one with reason *Superseded*. Scheduling that revocation a few days ahead gives you time to roll out.

## Using the certificates for mTLS

Every CA publishes its CRL at two public URLs (no login needed):

```
https://certly.lan/crl/<ca-id>.crl    # DER: embedded in issued certs when CERTLY_BASE_URL is set
https://certly.lan/crl/<ca-id>.pem    # PEM: what nginx's ssl_crl expects
```

The URLs are shown on the CA's page. The CRL to use is the one from the CA that issued your **client** certificates, normally the intermediate.

### nginx

```nginx
server {
    listen 443 ssl;
    server_name app.lan;

    ssl_certificate         /etc/nginx/certly/app.fullchain.pem;  # "Full chain" export
    ssl_certificate_key     /etc/nginx/certly/app.key.pem;        # "Private key" export

    ssl_client_certificate  /etc/nginx/certly/ca-chain.pem;       # intermediate + root
    ssl_verify_client       on;
    ssl_verify_depth        2;
    ssl_crl                 /etc/nginx/certly/crl.pem;            # refreshed by the timer below
}
```

nginx reads the CRL file only at startup or reload, so refresh it on a schedule. When the CRL expires, nginx rejects **every** client, which is why Certly re-signs CRLs well before their `nextUpdate`.

```sh
# /etc/cron.d/certly-crl: every 15 minutes
*/15 * * * * root curl -fsS -o /etc/nginx/certly/crl.pem.new https://certly.lan/crl/2.pem && mv /etc/nginx/certly/crl.pem.new /etc/nginx/certly/crl.pem && nginx -s reload
```

### Traefik (v3)

```yaml
# dynamic configuration
tls:
  options:
    mtls:
      clientAuth:
        caFiles: [/etc/traefik/certly/ca-chain.pem]
        clientAuthType: RequireAndVerifyClientCert
```

Traefik doesn't check CRLs itself. If you need revocation enforced, put nginx or HAProxy in front, or keep client certificates short-lived.

### HAProxy

```
bind :443 ssl crt /etc/haproxy/certly/app.pem ca-file /etc/haproxy/certly/ca-chain.pem verify required crl-file /etc/haproxy/certly/crl.pem
```

`app.pem` is the full chain followed by the key. HAProxy also needs a reload to pick up a new CRL.

### Clients

```sh
curl --cert laptop.crt.pem --key laptop.key.pem --cacert ca.pem https://app.lan/
```

Browsers and phones should import the `.p12` instead.

## Backup and restore

A backup contains the database: certificates, CA and leaf keys (**still encrypted with the master key**), revocations, CRLs and the audit log. It's taken with SQLite's `VACUUM INTO`, so it's consistent even while Certly is running.

> ⚠️ **The master key is never in a backup.** Without it, the keys in a backup can't be decrypted. Keep `master.key` in a password manager or another safe place, **separately** from the backups. If you lose it, you lose your CAs.

```sh
# Ad hoc (safe while running)
certly backup -o /root/certly-backup.tar.gz
# Timestamped into a directory, keep the newest 14, encrypted
CERTLY_BACKUP_PASSPHRASE='long passphrase' certly backup -dir /var/lib/certly/backups -keep 14 -encrypt
```

- **From the UI:** go to **Settings → Backup**. It asks for your password again, and the passphrase is optional.
- **Nightly:** `deploy/certly-backup.timer` runs `certly backup -dir /var/lib/certly/backups -keep 14` at 03:15. To encrypt, put `CERTLY_BACKUP_PASSPHRASE=…` in `/etc/certly/backup.env` (mode 0600) and add `-encrypt` to `ExecStart` in `certly-backup.service`.
- **Off-host:** copy the backups directory to another machine or a NAS with your usual tools.
- **Encryption format:** encrypted backups (`.tar.gz.age`) use [age](https://age-encryption.org) with a passphrase, so `age -d` can decrypt them as well as Certly.

**Restoring:**
```sh
sudo systemctl stop certly                 # restore refuses to run while Certly is running
sudo -u certly certly restore /path/to/certly-20261120T031500Z.tar.gz.age
# make sure CERTLY_MASTER_KEY_FILE is the key that belongs to this backup
sudo systemctl start certly
```

Before replacing anything, restore checks the backup:
- the archive contains only the two expected files
- the checksum matches
- the schema version is one this Certly understands
- SQLite's integrity check passes

The current database is kept as `certly.db.pre-restore`. If the master key doesn't match the restored database, `certly serve` refuses to start with a clear error.

## Running behind a reverse proxy

Pass the original host and the client IP through, and tell Certly which proxy to trust:

```nginx
location / {
    proxy_pass         http://127.0.0.1:8080;
    proxy_set_header   Host              $host;
    proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Host  $host;
    proxy_set_header   X-Forwarded-Proto $scheme;
    client_max_body_size 2m;
}
```

```sh
CERTLY_TRUSTED_PROXIES=127.0.0.1/32   # the proxy's address
CERTLY_SECURE_COOKIES=true            # the proxy terminates TLS
```

### "Request blocked" or "Origin does not match Host"

Every form submission is checked so that other websites can't submit forms to Certly in your name (CSRF). Over plain HTTP, browsers don't send the `Sec-Fetch-Site` header, so Certly compares the page's `Origin` with the request's `Host` instead. If something in between changes `Host` (a proxy, Docker or VM port forwarding, a tunnel), the two no longer match and the request is refused. The error page and the server log show both values. To fix it, do one of these:

- make the proxy forward the original host (`proxy_set_header Host $host;`), or
- list the proxy in `CERTLY_TRUSTED_PROXIES` so its `X-Forwarded-Host` is used, or
- add the URL you type in the browser to `CERTLY_ALLOWED_ORIGINS`, e.g. `CERTLY_ALLOWED_ORIGINS=http://192.168.1.10:8080`.

## Command-line reference

```
certly serve                         run the web app
certly admin create   [-username U]  create the admin account (only if none exists)
certly admin reset-password -username U   (signs out every session)
certly admin disable-totp   -username U   (if you lose your authenticator)
certly backup  -o FILE | -dir DIR [-keep N] [-encrypt]
certly restore FILE
certly import  -cert FILE [-key FILE] [-key-password-stdin] [-notes TEXT]
certly healthcheck                   exit 0 if the local server answers /healthz
certly version
```

**Locked out?** After 5 failed logins in 15 minutes, logins from that IP **and** for that username are blocked for 15 minutes. Restarting the service clears the lockout. `certly admin reset-password` resets the password if you've forgotten it.

## Security model

**What Certly protects:**
- Private keys are encrypted at rest with AES-256-GCM under the master key. Each key is bound to its own database row, so it can't be swapped onto another record.
- A stolen database or backup reveals no keys without the master key.
- The database, master key and backups are created `0600`, and the data directory `0700`.

**Web hardening:**
- One admin account: argon2id passwords (64 MiB, t=3), optional TOTP with replay protection, and login lockout.
- Sessions use `HttpOnly` cookies with `SameSite=Strict` (`Secure` and `__Host-` over HTTPS). The token is renewed on login, and sessions are invalidated when the password changes. There's a 12-hour lifetime and a 2-hour idle timeout.
- CSRF has two layers: a per-session token, plus checking the `Origin`/`Sec-Fetch-Site` headers with Go's `CrossOriginProtection`.
- A strict Content Security Policy (no inline scripts or styles), `frame-ancestors 'none'`, `nosniff`, `no-referrer`, and `no-store` caching for pages.
- Request bodies are capped at 1 MiB, and server timeouts guard against slow clients.

**PKI rules:**
- Serial numbers are 128-bit random.
- No SHA-1 or MD5 anywhere, and RSA keys must be at least 2048 bits.
- Leaf certificates are always `CA:FALSE`.
- Path lengths are enforced.
- CSR contents beyond the public key are ignored.
- Legacy (MD5-based) encrypted PEM keys are refused on import.

**Logging:** the audit log records every login, issue, export, revocation, import, backup, and password or TOTP change, with the client IP. Request logs contain only the method and path, never query strings, bodies, passwords or keys.

**Your responsibilities:**
- **Use HTTPS.** Either set `CERTLY_TLS_CERT`/`CERTLY_TLS_KEY`, using a server certificate Certly issued for itself, or run it behind a TLS reverse proxy with `CERTLY_SECURE_COOKIES=true` (or an `https://` `CERTLY_BASE_URL`). Without HTTPS, the dashboard shows a warning.
- **Don't expose Certly to the internet.** Use your LAN or a VPN. Only `/crl/*` and `/healthz` work without login, and the CRL is the only route that has to be reachable from where your services run.
- **Guard the master key** and the host. Anyone with root on the host, or with the master key plus the database, has your CAs.
- Turn on **TOTP**, and keep the OS and the Certly version up to date.

Found a vulnerability? See [SECURITY.md](SECURITY.md).

## Upgrading

1. Take a backup: `certly backup -o pre-upgrade.tar.gz`.
2. Swap the binary, or `docker compose pull`.
3. Restart. Database migrations run automatically on startup, and are forward-only.

An older binary refuses to open a database written by a newer one, so you can't downgrade by accident. To roll back, restore your pre-upgrade backup with the old binary.

## Development

You need Go 1.27+ (see `go.mod`). CGO is not used: SQLite is the pure-Go `modernc.org/sqlite`.

```sh
CGO_ENABLED=0 go build -o bin/certly ./cmd/certly
go test ./...                         # unit + HTTP integration tests
CERTLY_DATA_DIR=./data ./bin/certly serve
```

Before opening a PR, run:

```sh
gofmt -l . ; go vet ./... ; staticcheck ./...
govulncheck ./... ; gosec ./... ; osv-scanner scan source -r .
```

CI runs all of these plus a race-detector run, CodeQL, a Docker build with a smoke test, and a Trivy image scan. GitHub Actions are pinned to commit SHAs, and Dependabot keeps Go modules, Actions and base images current. Tagging `vX.Y.Z` builds release binaries (with checksums) and multi-arch images with SBOM and provenance.

[CLAUDE.md](CLAUDE.md) covers the architecture, conventions and the security rules every change has to follow.

## License

Licensed under the [Apache License 2.0](LICENSE). Copyright 2026 Kristo Copani. See [NOTICE](NOTICE).
