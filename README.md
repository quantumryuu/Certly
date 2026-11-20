# Certly: a small private CA for homelab mTLS

A self-hosted web app for running your own certificate authority (CA). It issues certificates for mutual TLS (mTLS), exports them in common formats and handles revocation. It ships as one static Go binary that runs on a plain Linux VM or in Docker.

> **Status: early development.** Nothing below is implemented yet. The README describes the planned design and will be updated as features land. Don't use it for anything you care about yet.

## Features (planned for v1)

- **CA hierarchy:** a root CA plus optional intermediate CAs
- **Certificates:** client certs (clientAuth) and server certs (serverAuth, with SANs). Key types are ECDSA P-256 (default), RSA 2048/4096 and Ed25519.
- **Export formats:** PEM (cert, key, chain, fullchain), DER, PKCS#12 (`.p12`/`.pfx`) and encrypted PKCS#8 keys
- **Downloads:** a single file or a zip bundle. Password protection encrypts the key or P12 itself with AES-256, not the zip.
- **Revocation:** revoke now or on a set date, with an RFC 5280 reason code
- **CRL:** each CA has a public CRL at `/crl/<ca-id>.crl`, and its URL is embedded in every cert the CA issues. Works with nginx, Traefik and HAProxy.
- **Expiry tracking:** the dashboard shows certificates that expire soon
- **Security:**
  - private keys encrypted at rest with a master key
  - a single admin with argon2id password hashing and optional TOTP
  - audit log of every action
- **Backup and restore:** a consistent snapshot while the app is running, from the CLI or the UI, with optional encryption
- **Import:** bring in existing CAs and certificates from your old scripts

## Quick start

### Docker

```sh
git clone https://github.com/quantumryuu/Certly.git && cd Certly
docker compose up -d
# open http://localhost:8080 and create the admin account
```

Data, including the database and the master key if it's generated, lives in the `certly-data` volume mounted at `/data`.

### Bare Linux (systemd)

```sh
# 1. Download the binary for your arch from https://github.com/quantumryuu/Certly/releases
sudo install -m 0755 certly /usr/local/bin/certly

# 2. Create a dedicated user and data dir
sudo useradd --system --home /var/lib/certly --shell /usr/sbin/nologin certly
sudo install -d -o certly -g certly -m 0700 /var/lib/certly

# 3. Install and start the service
sudo cp deploy/certly.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now certly
```

## Configuration

Settings come from environment variables, and every one also has a matching CLI flag.

| Variable | Default | Description |
|---|---|---|
| `CERTLY_LISTEN` | `:8080` | Address to listen on |
| `CERTLY_DATA_DIR` | `/var/lib/certly` (Docker: `/data`) | Where the database and generated files live |
| `CERTLY_BASE_URL` | `http://localhost:8080` | Public URL. It is used for the CRL distribution point in issued certs, so set it **before** you issue anything. |
| `CERTLY_MASTER_KEY_FILE` | `$CERTLY_DATA_DIR/master.key` | File holding the 32-byte master key. It's generated on first run if missing. |
| `CERTLY_TLS_CERT` / `CERTLY_TLS_KEY` | *(empty)* | Serve HTTPS directly. If empty, the app expects a TLS reverse proxy in front of it. |
| `CERTLY_LOG_FORMAT` | `text` | `text` or `json` |

## First run

1. Open the UI and create the admin account. On a headless host you can use `certly admin create` instead.
2. Create a **root CA**. Use a long validity (e.g. 10 years) and don't use it for day-to-day signing.
3. Create an **intermediate CA** signed by the root (e.g. 3–5 years). Issue all leaf certificates from it.
4. Issue a **server certificate** for each service and a **client certificate** for each user or device.

## Operating it

### Exporting

On a certificate's page, click **Download** and pick the format:

| Format | Contains | Typical use |
|---|---|---|
| PEM | cert / key / chain / fullchain | nginx, HAProxy, Traefik, curl |
| DER | cert | Java, Windows, some appliances |
| PKCS#12 (`.p12`/`.pfx`) | cert + key + chain, password protected | Browsers, macOS/iOS/Android, Windows |
| Encrypted PKCS#8 | key, password protected | Moving a key safely |
| Zip bundle | any combination of the above + a CA chain | Handing everything to a device in one go |

### Revoking

Open the certificate, click **Revoke**, then choose **Now** or a **date**, and a reason. A background job applies scheduled revocations. The CRL is regenerated whenever a cert is revoked and also on a timer.

### Using it for mTLS (nginx example)

```nginx
server {
    listen 443 ssl;
    ssl_certificate         /etc/nginx/certs/server.fullchain.pem;
    ssl_certificate_key     /etc/nginx/certs/server.key;

    ssl_client_certificate  /etc/nginx/certs/ca-chain.pem;   # intermediate + root
    ssl_verify_client       on;
    ssl_verify_depth        2;
    ssl_crl                 /etc/nginx/certs/ca.crl;         # refresh periodically, see below
}
```

To keep the CRL current, fetch it on a schedule and reload nginx:

```sh
curl -fsSo /etc/nginx/certs/ca.crl https://certly.lan/crl/<ca-id>.crl && nginx -s reload
```

Traefik and Caddy examples will be added later.

## Backup and restore

```sh
certly backup -o /backups/certly-$(date +%F).tar.gz            # safe while running
certly backup -o backup.tar.gz.enc --encrypt                  # passphrase-encrypted
sudo systemctl stop certly && certly restore backup.tar.gz && sudo systemctl start certly
```

A backup contains the database (certificates, CA keys encrypted at rest, revocations and the audit log) plus a manifest.

> ⚠️ **The master key is deliberately left out of backups.** Store `master.key` separately, e.g. in a password manager. Without it, your backups can't be used. If you lose it, you lose your CAs.

There's a systemd timer for nightly backups at `deploy/certly-backup.timer`. For continuous replication you can use Litestream, but that's optional.

### Upgrading

Back up first, replace the binary or pull the new image, then restart. Database migrations run automatically on startup.

## Security notes

- Don't expose this app to the internet. Reach it over your LAN or a VPN. The only routes that work without logging in are `/crl/*`.
- Always use HTTPS: either a reverse proxy, or `CERTLY_TLS_CERT`/`CERTLY_TLS_KEY` with a server cert the app issued itself.
- Protect `CERTLY_DATA_DIR` and the master key file. Both should be `0700`/`0600` and owned by the service user.
- Turn on TOTP for the admin account.
- To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Development

You need Go 1.27+ (see `go.mod`). CGO is not required.

```sh
CGO_ENABLED=0 go build -o bin/certly ./cmd/certly
go test ./...
CERTLY_DATA_DIR=./data ./bin/certly serve
```

Before opening a PR, also run `go vet ./...`, `staticcheck ./...`, `govulncheck ./...` and `gosec ./...`. See [CLAUDE.md](CLAUDE.md) for architecture and conventions.

## License

Licensed under the [Apache License 2.0](LICENSE). Copyright 2026 Kristo Copani. See [NOTICE](NOTICE).
