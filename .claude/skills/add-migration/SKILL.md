---
name: add-migration
description: Add a database schema change as a SQL migration in internal/store/migrations. Use whenever a table, column or index changes.
---

# Add a migration

Certly uses a small built-in migrator (`internal/store/store.go`). It runs the embedded `migrations/NNNNN_name.sql` files in order. Each file runs in its own transaction and is recorded in `schema_migrations`. Migrations are **forward-only**: there is no "down".

1. Never edit an existing migration that has been merged. Always add a new one.
2. Create `internal/store/migrations/NNNNN_short_name.sql`, where NNNNN is one more than the current highest number (5 digits, zero-padded, no gaps; the migrator refuses gaps):
   ```sql
   ALTER TABLE certificates ADD COLUMN profile TEXT NOT NULL DEFAULT '';
   ```
3. SQLite caveats:
   - New tables use `STRICT`.
   - Timestamps are UTC text in `store.TimeFormat` (`2006-01-02T15:04:05Z`), so that comparing strings compares times.
   - For complex column changes, use the create-copy-drop-rename pattern inside one migration file.
   - Don't put `BEGIN`/`COMMIT` in the file. The migrator already wraps it in a transaction.
4. Never add a column that holds secret material in plaintext. Key columns hold the sealed envelope from `internal/crypto`, with AAD that binds it to its row.
5. Update the structs and queries in `internal/store/queries.go`. Use `?` parameters only and never concatenate values into SQL.
6. Run `go test ./internal/store/... ./internal/backup/... -count=1`. The store tests run all migrations on a fresh DB, and the backup tests restore and migrate a snapshot.
7. An older binary refuses to open a DB with a newer schema, and restore migrates older backups forward. Mention the migration in the README's **Upgrading** section if it's slow or irreversible.
