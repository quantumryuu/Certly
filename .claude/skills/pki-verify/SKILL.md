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

## 3. mTLS end to end (Docker)
1. Start nginx with the server cert, `ssl_client_certificate intermediate+root`, `ssl_verify_client on` and `ssl_crl ca.crl`.
2. Run `curl --cert client.crt --key client.key --cacert root.crt https://localhost` → expect **200**.
3. Revoke the client cert in the app, download the new CRL and reload nginx.
4. Run the same curl again → expect a **400** (`The SSL certificate error`).
5. Scheduled revocation: set `revoke_at` a minute ahead and confirm the job revokes the cert and the CRL updates.

Report every check as pass or fail with the command output. Never report a check as passing without running it.
