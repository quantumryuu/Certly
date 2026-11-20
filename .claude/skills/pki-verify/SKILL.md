---
name: pki-verify
description: Verify PKI output (certs, chains, CRLs, P12, encrypted keys) with openssl and run the nginx mTLS end-to-end check. Use after changing anything in internal/pki, export code, or revocation logic.
---

# Verify PKI output

Work in a temporary directory, never in the repo. Use throwaway keys only.

## 1. Unit tests
```sh
go test ./internal/pki/... ./internal/jobs/... -count=1
```

## 2. Cross-check with openssl
Issue a root, an intermediate, a server cert and a client cert with a dev instance (`CERTLY_DATA_DIR=$(mktemp -d) ./bin/certly serve`) or the test helpers, then export them. Check:

```sh
openssl x509 -in leaf.crt -noout -text          # EKU, SANs, CDP URL, key usage
openssl verify -CAfile root.crt -untrusted intermediate.crt leaf.crt
openssl crl -inform DER -in ca.crl -noout -text # revoked serials, reason, nextUpdate
openssl pkcs12 -info -in bundle.p12 -noout -passin pass:test   # must use AES, not RC2/3DES
openssl pkey -in key.enc.pem -passin pass:test -noout
```

What to expect:
- Client certs have EKU `TLS Web Client Authentication`. Server certs have `TLS Web Server Authentication` and the SANs that were requested.
- CA certs have `CA:TRUE` with the intended pathlen. Leaf certs have `CA:FALSE`.
- No SHA-1 signatures.

## 3. mTLS end to end
Work in a scratch directory. Run a dev instance (`CERTLY_DATA_DIR=$(mktemp -d) CERTLY_BASE_URL=http://127.0.0.1:18080 CERTLY_LISTEN=127.0.0.1:18080 ./bin/certly serve`), create the admin with `printf 'pw...\n' | certly admin create`, and drive the UI with curl. Each POST needs the `csrf` field taken from the page.

1. Issue a server cert (SAN `localhost`, `127.0.0.1`) and a client cert from the intermediate. Export the fullchain and key for both, and download `GET /crl/<inter-id>.pem`.
2. Start the TLS server, and **always** pass `-verify_return_error`, otherwise s_server accepts failed verifications:
   ```sh
   openssl s_server -accept 127.0.0.1:18443 -cert server.fullchain.pem -key server.key \
     -CAfile ca-chain.pem -Verify 2 -verify_return_error -crl_check -CRL crl.pem -www -quiet
   ```
3. Run `curl --cacert root.pem --cert client.pem --key client.key https://localhost:18443/` → expect **200**.
4. Without `--cert`, the handshake must fail (curl exit 56).
5. Revoke the client cert in the app, download the CRL again and restart s_server. The same curl must fail with the s_server log showing `certificate revoked`.
6. For scheduled revocation, set it a minute or two ahead. The job runs every minute; afterwards the CRL must list the serial.
7. If nginx or Docker is available, repeat with nginx (`ssl_verify_client on; ssl_crl crl.pem;`), which expects a **PEM** CRL.

Report every check as pass or fail with the command output. Never report a check as passing without running it.
