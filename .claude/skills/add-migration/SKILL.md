---
name: add-migration
description: Add a database schema change as a goose SQL migration in internal/store/migrations. Use whenever a table, column or index changes.
---

# Add a migration

1. Never edit an existing migration that has been merged. Always add a new one.
2. Create `internal/store/migrations/NNNNN_short_name.sql`, where NNNNN is one more than the current highest number (zero-padded to 5 digits):
   ```sql
   -- +goose Up
   ALTER TABLE certificates ADD COLUMN revoke_at TIMESTAMP NULL;

   -- +goose Down
   ALTER TABLE certificates DROP COLUMN revoke_at;
   ```
3. SQLite caveats:
   - Use `STRICT` tables for new tables.
   - Store timestamps as UTC ISO-8601 text.
   - For complex column changes, use the create-copy-drop-rename pattern inside one migration.
4. Never store secret material in a new column in plain form. Key columns hold the encrypted envelope from `internal/crypto`.
5. Update the repository code and structs in `internal/store/`.
6. Run `go test ./internal/store/... -count=1`. The tests run every migration up and down on a fresh DB.
7. Backups record the schema version, and restore applies migrations forward. Check that `internal/backup` restore tests still pass.
