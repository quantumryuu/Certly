-- Initial schema. Timestamps are UTC text in the format 2006-01-02T15:04:05Z,
-- so they compare correctly as strings.

CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    totp_secret   BLOB,             -- encrypted with the master key; NULL = TOTP off
    created_at    TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL
) STRICT;

CREATE TABLE certificates (
    id                INTEGER PRIMARY KEY,
    kind              TEXT    NOT NULL CHECK (kind IN ('root','intermediate','client','server','client-server')),
    common_name       TEXT    NOT NULL,
    subject           TEXT    NOT NULL,
    serial            TEXT    NOT NULL,          -- uppercase hex
    issuer_id         INTEGER REFERENCES certificates(id),
    key_type          TEXT    NOT NULL,
    not_before        TEXT    NOT NULL,
    not_after         TEXT    NOT NULL,
    sans              TEXT    NOT NULL DEFAULT '',
    cert_der          BLOB    NOT NULL,
    key_enc           BLOB,                      -- encrypted PKCS#8; NULL = no key stored
    revoked_at        TEXT,                      -- set once revocation is in effect
    revoke_at         TEXT,                      -- scheduled revocation time
    revocation_reason INTEGER,
    notes             TEXT    NOT NULL DEFAULT '',
    imported          INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT    NOT NULL,
    UNIQUE (issuer_id, serial)
) STRICT;

CREATE INDEX certificates_issuer   ON certificates(issuer_id);
CREATE INDEX certificates_notafter ON certificates(not_after);
CREATE INDEX certificates_revoke   ON certificates(revoke_at) WHERE revoke_at IS NOT NULL AND revoked_at IS NULL;

CREATE TABLE crls (
    ca_id       INTEGER PRIMARY KEY REFERENCES certificates(id),
    number      INTEGER NOT NULL,
    this_update TEXT    NOT NULL,
    next_update TEXT    NOT NULL,
    der         BLOB    NOT NULL
) STRICT;

CREATE TABLE audit_log (
    id        INTEGER PRIMARY KEY,
    at        TEXT    NOT NULL,
    actor     TEXT    NOT NULL,
    action    TEXT    NOT NULL,
    target_id INTEGER,
    detail    TEXT    NOT NULL DEFAULT '',
    remote_ip TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX audit_log_at ON audit_log(at);

-- Used by github.com/alexedwards/scs/sqlite3store.
CREATE TABLE sessions (
    token  TEXT PRIMARY KEY,
    data   BLOB NOT NULL,
    expiry REAL NOT NULL
) STRICT;

CREATE INDEX sessions_expiry ON sessions(expiry);
