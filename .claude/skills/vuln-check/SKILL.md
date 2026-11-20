---
name: vuln-check
description: Scan for CVEs and insecure code and review the current change like an attacker would. Run on every change before calling it done, and when bumping Go or dependency versions.
---

# Vulnerability and security check

You are reviewing as an offensive and defensive security expert. This app holds CA private keys, so if it is compromised, every mTLS-protected service in the homelab is compromised too.

## 1. Tools (install if missing: `go install golang.org/x/vuln/cmd/govulncheck@latest`, `github.com/securego/gosec/v2/cmd/gosec@latest`, `github.com/google/osv-scanner/v2/cmd/osv-scanner@latest`, `honnef.co/go/tools/cmd/staticcheck@latest`)
```sh
go version && go list -m -u all   # current Go version and dependencies with updates available
govulncheck ./...                 # known CVEs in code that is actually reachable (stdlib + deps)
osv-scanner scan source -r .      # CVEs in go.mod/go.sum and GitHub Actions
gosec -quiet ./...                # insecure code patterns
go vet ./... && staticcheck ./...
trivy image certly:dev            # only if the Dockerfile or base image changed
```
- If govulncheck reports something, upgrade the Go toolchain or the module in `go.mod` (or the `toolchain` line), then run it again.
- GitHub Actions in `.github/workflows/` must be pinned to a commit SHA, not a tag.

## 2. Manual threat review of the diff
Look at `git diff` (or the files you changed) and go through:
- **Auth:** every new route is behind the session middleware except `/crl/*`. Login is rate-limited. Password and TOTP checks are constant-time. The session is renewed on login.
- **CSRF:** every state-changing method (POST/PUT/DELETE) is protected. No state changes on GET.
- **Injection:** SQL uses parameters only. No user input in `exec.Command`. No `template.HTML` or `template.JS` on user data.
- **Files:** download names are sanitized (`Content-Disposition`). Restore rejects zip slip (`..` and absolute paths) and limits archive and file sizes.
- **Secrets:**
  - no keys, passwords, the master key or P12 passphrases in logs, errors, audit details or URLs
  - secret buffers are zeroed where it's practical
- **Crypto:**
  - randomness only from `crypto/rand`
  - no SHA-1, MD5, RC2 or 3DES
  - RSA keys are at least 2048 bits
  - AES-GCM nonces are never reused
  - argon2id parameters are at least m=64MiB, t=3
- **PKI logic:**
  - EKU, KeyUsage and BasicConstraints are correct
  - a leaf can never get `IsCA` set
  - pathlen is enforced
  - SAN input is validated
  - a revoked or expired CA can't sign
  - the CRL is signed by the correct CA
- **HTTP hardening:**
  - security headers: CSP, `X-Content-Type-Options`, `frame-ancestors 'none'`, `Referrer-Policy`, HSTS when served over TLS
  - session cookies are `Secure`/`HttpOnly`/`SameSite=Strict`
  - request body size limits
  - server timeouts (`ReadHeaderTimeout` etc.)
- **Container:** runs as non-root on distroless, uses no extra Linux capabilities, keeps data only in the `/data` volume.

## 3. Report
List each finding as: **issue → severity (critical/high/medium/low) → file:line → fix applied or reason it's accepted**. Include the tool output summary.

If the tools couldn't run (for example, there's no network), say so. Don't report the scan as clean.

If a finding changes what users need to know (for example, an upgrade is required), update the Security section of README.md.
