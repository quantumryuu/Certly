---
name: add-export-format
description: Add a new certificate or key export format (e.g. JKS, a new bundle layout) to the download and zip options. Use when extending what users can download.
---

# Add an export format

1. Add an `encXxx(b Bundle, opt ExportOptions, base string) (*File, error)` function in `internal/pki/export.go`. It gets the cert, its chain and the key (optional), plus an optional password, and returns the file name (built from `base`), content type and bytes. No HTTP and no DB code here.
2. Password rules:
   - If the format holds a private key and a password is given, encrypt with a modern algorithm (AES-256 / PBES2).
   - Never fall back to RC2, 3DES or plain MD5-based schemes without a password.
   - If the format can't hold a key safely, don't offer the key for that format.
3. Add it to `pki.Formats` with `NeedsKey`/`NeedsPass` set correctly. `pki.Export` enforces the password and CA-key rules from those flags, and the UI menu is built from the list automatically. Add it to `encZip` too if it belongs in the bundle.
4. Every export writes an audit log entry with the format and whether a key was included. `ca.Service.Export` already does this; make sure your format is reached through it.
5. Tests: decode the output again (or use openssl through the `pki-verify` skill) and check that the cert, chain and key match the input.
6. Add the format to the export formats table in README.md.
