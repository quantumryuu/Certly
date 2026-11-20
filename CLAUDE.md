# CLAUDE.md

Certly is a self-hosted web app for running a small private PKI for homelab mTLS. It issues root and intermediate CAs, and client and server certificates. It exports them in several formats, handles revocation (immediate or scheduled), publishes CRLs, and does backup and restore. It ships as one static Go binary, and the same binary is used in the Docker image.

This is a **public repo**. Never commit keys, certificates, `.env` files, DB files or real hostnames.

## Stack
- Go 1.27+ (module `github.com/quantumryuu/Certly`), router `go-chi/chi/v5`
- UI: `html/template` + HTMX + Pico.css, embedded with `embed.FS`. No JS build step and no SPA.
- Crypto: stdlib `crypto/x509` for certs and CRLs, `software.sslmate.com/src/go-pkcs12` (always `pkcs12.Modern`, with 600k iterations), `github.com/youmark/pkcs8` for encrypted keys (PBES2, PBKDF2-SHA256, AES-256-CBC), `filippo.io/age` for encrypted backups
- DB: SQLite via `modernc.org/sqlite`. Pure Go: **CGO must stay disabled**.
- Migrations: a small built-in migrator (`internal/store/store.go`) that runs embedded `NNNNN_name.sql` files in `internal/store/migrations/`. They are forward-only, each runs in its own transaction, and the result is tracked in `schema_migrations`.
- Auth: one admin user, argon2id password, optional TOTP (`pquerna/otp`), `alexedwards/scs` sessions in SQLite, CSRF protection (a session token plus stdlib `http.CrossOriginProtection`)

## Layout
| Path | Purpose |
|---|---|
| `cmd/certly/` | Entry point and subcommands: `serve`, `admin`, `backup`, `restore`, `import`, `healthcheck`. `config.go` is the single place that defines env vars and flags. |
| `internal/pki/` | Issuing certs, CRLs, profiles, encoders (PEM/DER/P12/PKCS#8/zip). Pure logic, no HTTP and no DB. |
| `internal/ca/` | Application service: issue, revoke, schedule, export, import, CRL generation, audit. The web UI, CLI and jobs all go through it. |
| `internal/auth/` | argon2id hashing, TOTP with replay protection, login rate limiter |
| `internal/store/` | SQLite repository + migrations. Only ever sees sealed key blobs. |
| `internal/crypto/` | Encrypts private keys at rest (AES-256-GCM with the master key) |
| `internal/backup/` | Snapshot (`VACUUM INTO`), tar.gz with manifest, optional age encryption, restore, data-dir lock |
| `internal/jobs/` | Background jobs: scheduled revocation, CRL refresh |
| `internal/web/` | Handlers, middleware, `templates/`, `static/` |
| `deploy/` | systemd unit (hardened), backup service + timer, example env file |

Dependencies point one way: `cmd` → `web` → `ca` → `store`/`pki`/`crypto`. `pki` and `crypto` import nothing internal. Handlers must not use `pki` + `store` directly for anything that needs auditing; go through `ca`.

## Commands
```sh
go build -o bin/certly ./cmd/certly          # CGO_ENABLED=0 always
go test ./...                                  # add -race with CGO_ENABLED=1 to check races
go vet ./... && staticcheck ./...
CERTLY_DATA_DIR=./data ./bin/certly serve     # dev run, http://localhost:8080
docker build -t certly . && docker compose up
```

## Security rules (do not break)
- Private keys are **never** written to the DB or disk unencrypted. Always go through `internal/crypto`.
- The master key is **never** included in backups, logs, exports or error messages.
- Every issue, revoke, export, backup and login gets an audit log entry.
- Serial numbers: 128-bit random from `crypto/rand`, never sequential.
- Default key type is ECDSA P-256. RSA must be at least 2048 bits. No SHA-1 and no MD5.
- Password-protected exports encrypt the key or P12 itself. We do **not** use encrypted zips.
- `/crl/*`, `/healthz` and `/static/*` are the only routes that skip auth (`/setup` and `/login` need a session, but not a login). Every other route needs a logged-in session, and every POST checks CSRF.
- Sealed key blobs are bound to their row with AAD (`cert-key:<id>`, `totp:<uid>`). Never seal without AAD.
- A CA can sign only if it and every CA above it are unrevoked and unexpired (`ca.Service.checkChain`).
- Every request body is capped at 1 MiB (`maxBody`). Don't raise it for one handler without a size limit of its own.
- Templates rely on `html/template` auto-escaping. Never use `template.HTML`/`template.URL` on user input. CSP forbids inline scripts and styles, so don't add `style=` or `<script>` blocks; put CSS in `static/app.css`.

## Conventions
- Errors: wrap with `fmt.Errorf("...: %w", err)`. Return errors and don't panic, except in `main`.
- Logging: `log/slog` (JSON when `CERTLY_LOG_FORMAT=json`).
- Config: only env vars and flags, defined in one place in `cmd/certly`. Document every new variable in the README table.
- Tests: table-driven. PKI tests must check the result with `x509.Verify` or by parsing it back, not just "no error".
- Schema changes always go in a new migration. Never edit a migration that has been merged.

## Required for every change
These steps are part of the change, not extras. Do them before saying a task is done.

1. **Keep README.md up to date.** Whenever a change affects what users see, update README.md in the same change. That includes:
   - features, the UI, CLI flags or subcommands
   - env vars, defaults or ports
   - export formats, deploy steps, backup and restore, upgrade notes or security notes

   If the README is already correct, say so explicitly. Don't skip this silently.
2. **Do a security review, thinking like an attacker.** Run the `vuln-check` skill. At minimum:
   - `govulncheck ./...` and `osv-scanner` for known CVEs in the Go toolchain and dependencies. Upgrade any vulnerable dependency or Go version you find, or explain why it isn't reachable.
   - `gosec ./...`, `go vet` and `staticcheck` for insecure code patterns
   - A manual threat review of the diff:
     - authn and authz bypass
     - CSRF
     - XSS and template escaping
     - SQL injection (parameterized queries only)
     - path traversal in downloads and restore (zip slip)
     - key material leaking into logs, errors or responses
     - weak crypto parameters
     - timing-safe comparisons
     - session fixation
     - brute force and rate limiting
     - SSRF
     - DoS through big uploads or slow requests
   - Dependency hygiene: before adding a dependency, check how well it's maintained, its security record and its license. Prefer the standard library.
   - Docker image: `trivy image` when the Dockerfile or base image changes
3. Report what you found as **issue → severity → fix or reason it's accepted**. Never claim "no vulnerabilities" without having run the tools.

## Skills
Project skills are in `.claude/skills/`:
- `vuln-check`: CVE scan plus a threat review of the change (run it on every change)
- `pki-verify`: check issued certs, CRLs and exports with openssl, and run the mTLS end-to-end test (`openssl s_server`)
- `add-migration`: add a schema migration the right way
- `add-export-format`: add a new download or export format
