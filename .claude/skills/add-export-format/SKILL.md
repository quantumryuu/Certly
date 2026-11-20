---
name: add-export-format
description: Add a new certificate or key export format (e.g. JKS, a new bundle layout) to the download and zip options. Use when extending what users can download.
---

# Add an export format

1. Put the encoder in `internal/pki/export/`. Implement the shared encoder interface: given the cert, its chain, the key (optional) and an optional password, return the file name, content type and bytes. No HTTP and no DB code here.
2. Password rules:
   - If the format holds a private key and a password is given, encrypt with a modern algorithm (AES-256 / PBES2).
   - Never fall back to RC2, 3DES or plain MD5-based schemes without a password.
   - If the format can't hold a key safely, don't offer the key for that format.
3. Register the format in the export registry so it shows in the UI download menu and can go into the zip bundle.
4. Add the matching option to the template in `internal/web/templates/` (an HTMX partial).
5. Every export writes an audit log entry with the format and whether a key was included. This already happens in the handler; check that it does.
6. Tests: decode the output again (or use openssl through the `pki-verify` skill) and check that the cert, chain and key match the input.
7. Add the format to the export formats table in README.md.
