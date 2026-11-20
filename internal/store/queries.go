package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ---- users ----

// User is the admin account.
type User struct {
	ID           int64
	Username     string
	PasswordHash string
	TOTPSecret   []byte // sealed; nil = TOTP disabled
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// CountUsers returns how many users exist.
func (s *Store) CountUsers(ctx context.Context) (int, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		return 0, fmt.Errorf("store: count users: %w", err)
	}
	return n, nil
}

// CreateFirstUser creates the admin only if no user exists yet, atomically,
// so two concurrent setup requests can't both succeed.
func (s *Store) CreateFirstUser(ctx context.Context, username, hash string) (int64, error) {
	now := Fmt(time.Now())
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, created_at, updated_at)
		 SELECT ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)`, username, hash, now, now)
	if err != nil {
		return 0, fmt.Errorf("store: create user: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return 0, errors.New("store: an admin user already exists")
	}
	return res.LastInsertId()
}

func scanUser(row *sql.Row) (*User, error) {
	var u User
	var created, updated string
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.TOTPSecret, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: get user: %w", err)
	}
	u.CreatedAt, u.UpdatedAt = Parse(created), Parse(updated)
	return &u, nil
}

const userCols = `id, username, password_hash, totp_secret, created_at, updated_at`

// UserByName finds a user by username.
func (s *Store) UserByName(ctx context.Context, name string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE username = ?`, name))
}

// UserByID finds a user by id.
func (s *Store) UserByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id = ?`, id))
}

// SetPassword updates a password hash.
func (s *Store) SetPassword(ctx context.Context, id int64, hash string) error {
	return s.execOne(ctx, `UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?`, hash, Fmt(time.Now()), id)
}

// SetTOTP stores a sealed TOTP secret, or clears it with nil.
func (s *Store) SetTOTP(ctx context.Context, id int64, sealed []byte) error {
	return s.execOne(ctx, `UPDATE users SET totp_secret = ?, updated_at = ? WHERE id = ?`, sealed, Fmt(time.Now()), id)
}

func (s *Store) execOne(ctx context.Context, q string, args ...any) error {
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ---- certificates ----

// Cert is a stored certificate (CA or leaf).
type Cert struct {
	ID         int64
	Kind       string
	CommonName string
	Subject    string
	Serial     string
	IssuerID   sql.NullInt64
	KeyType    string
	NotBefore  time.Time
	NotAfter   time.Time
	SANs       string
	DER        []byte
	KeyEnc     []byte // sealed PKCS#8; nil when no key is stored
	RevokedAt  *time.Time
	RevokeAt   *time.Time
	Reason     sql.NullInt64
	Notes      string
	Imported   bool
	CreatedAt  time.Time
	IssuerName string // filled by queries that join the issuer
}

// IsCA reports whether the cert is a CA.
func (c *Cert) IsCA() bool { return c.Kind == "root" || c.Kind == "intermediate" }

// HasKey reports whether a private key is stored.
func (c *Cert) HasKey() bool { return len(c.KeyEnc) > 0 }

// Status is a display status at time now.
func (c *Cert) Status(now time.Time) string {
	switch {
	case c.RevokedAt != nil:
		return "revoked"
	case now.After(c.NotAfter):
		return "expired"
	case now.Before(c.NotBefore):
		return "not yet valid"
	case c.RevokeAt != nil:
		return "revocation scheduled"
	default:
		return "valid"
	}
}

// Usable reports whether a CA can sign right now.
func (c *Cert) Usable(now time.Time) bool {
	if !c.IsCA() || !c.HasKey() {
		return false
	}
	st := c.Status(now)
	return st == "valid" || st == "revocation scheduled"
}

const certCols = `c.id, c.kind, c.common_name, c.subject, c.serial, c.issuer_id, c.key_type, c.not_before, c.not_after,
	c.sans, c.cert_der, c.key_enc, c.revoked_at, c.revoke_at, c.revocation_reason, c.notes, c.imported, c.created_at,
	COALESCE(i.common_name, '')`

const certFrom = ` FROM certificates c LEFT JOIN certificates i ON i.id = c.issuer_id `

type scanner interface{ Scan(...any) error }

func scanCert(r scanner) (*Cert, error) {
	var c Cert
	var nb, na, created string
	var revokedAt, revokeAt sql.NullString
	var imported int
	if err := r.Scan(&c.ID, &c.Kind, &c.CommonName, &c.Subject, &c.Serial, &c.IssuerID, &c.KeyType, &nb, &na,
		&c.SANs, &c.DER, &c.KeyEnc, &revokedAt, &revokeAt, &c.Reason, &c.Notes, &imported, &created, &c.IssuerName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scan cert: %w", err)
	}
	c.NotBefore, c.NotAfter, c.CreatedAt = Parse(nb), Parse(na), Parse(created)
	if revokedAt.Valid {
		t := Parse(revokedAt.String)
		c.RevokedAt = &t
	}
	if revokeAt.Valid {
		t := Parse(revokeAt.String)
		c.RevokeAt = &t
	}
	c.Imported = imported != 0
	return &c, nil
}

// InsertCertTx stores a certificate without its key. The sealed key's AAD
// includes the row id, so callers then call SetCertKeyTx in the same tx.
func (s *Store) InsertCertTx(ctx context.Context, tx *sql.Tx, c *Cert) (int64, error) {
	var issuer any
	if c.IssuerID.Valid {
		issuer = c.IssuerID.Int64
	}
	imported := 0
	if c.Imported {
		imported = 1
	}
	res, err := tx.ExecContext(ctx, `INSERT INTO certificates
		(kind, common_name, subject, serial, issuer_id, key_type, not_before, not_after, sans, cert_der, notes, imported, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Kind, c.CommonName, c.Subject, c.Serial, issuer, c.KeyType, Fmt(c.NotBefore), Fmt(c.NotAfter), c.SANs, c.DER, c.Notes, imported, Fmt(time.Now()))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return 0, errors.New("store: a certificate with this serial already exists")
		}
		return 0, fmt.Errorf("store: insert cert: %w", err)
	}
	return res.LastInsertId()
}

// SetCertKeyTx stores the sealed key for a certificate.
func (s *Store) SetCertKeyTx(ctx context.Context, tx *sql.Tx, id int64, sealed []byte) error {
	_, err := tx.ExecContext(ctx, `UPDATE certificates SET key_enc = ? WHERE id = ?`, sealed, id)
	if err != nil {
		return fmt.Errorf("store: set key: %w", err)
	}
	return nil
}

// Tx runs fn in a transaction.
func (s *Store) Tx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// CertByID fetches one certificate.
func (s *Store) CertByID(ctx context.Context, id int64) (*Cert, error) {
	return scanCert(s.db.QueryRowContext(ctx, `SELECT `+certCols+certFrom+`WHERE c.id = ?`, id))
}

// CertFilter narrows ListCerts.
type CertFilter struct {
	CAs      bool   // true: only CAs; false: only leaf certs
	IssuerID int64  // 0 = any
	Search   string // matches CN, SANs, serial
	Status   string // "", "valid", "revoked", "expired", "scheduled"
	Limit    int
	Offset   int
}

// ListCerts lists certificates, newest first.
func (s *Store) ListCerts(ctx context.Context, f CertFilter, now time.Time) ([]*Cert, error) {
	var where []string
	var args []any
	if f.CAs {
		where = append(where, `c.kind IN ('root','intermediate')`)
	} else {
		where = append(where, `c.kind NOT IN ('root','intermediate')`)
	}
	if f.IssuerID > 0 {
		where = append(where, `c.issuer_id = ?`)
		args = append(args, f.IssuerID)
	}
	if q := strings.TrimSpace(f.Search); q != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q) + "%"
		where = append(where, `(c.common_name LIKE ? ESCAPE '\' OR c.sans LIKE ? ESCAPE '\' OR c.serial LIKE ? ESCAPE '\')`)
		args = append(args, like, like, like)
	}
	n := Fmt(now)
	switch f.Status {
	case "valid":
		where = append(where, `c.revoked_at IS NULL AND c.not_after > ?`)
		args = append(args, n)
	case "revoked":
		where = append(where, `c.revoked_at IS NOT NULL`)
	case "expired":
		where = append(where, `c.revoked_at IS NULL AND c.not_after <= ?`)
		args = append(args, n)
	case "scheduled":
		where = append(where, `c.revoked_at IS NULL AND c.revoke_at IS NOT NULL`)
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 500
	}
	// Only constant fragments are joined; every value is a ? parameter.
	q := `SELECT ` + certCols + certFrom + `WHERE ` + strings.Join(where, ` AND `) + ` ORDER BY c.id DESC LIMIT ? OFFSET ?` // #nosec G202
	args = append(args, limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list certs: %w", err)
	}
	defer rows.Close()
	var out []*Cert
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Expiring lists unrevoked certs that expire between now and now+within.
func (s *Store) Expiring(ctx context.Context, now time.Time, within time.Duration) ([]*Cert, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+certCols+certFrom+
		`WHERE c.revoked_at IS NULL AND c.not_after > ? AND c.not_after <= ? ORDER BY c.not_after LIMIT 100`,
		Fmt(now), Fmt(now.Add(within)))
	if err != nil {
		return nil, fmt.Errorf("store: expiring: %w", err)
	}
	defer rows.Close()
	var out []*Cert
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Stats are dashboard counters.
type Stats struct {
	CAs, Valid, Revoked, Expired, Scheduled int
}

// GetStats computes dashboard counters.
func (s *Store) GetStats(ctx context.Context, now time.Time) (Stats, error) {
	var st Stats
	n := Fmt(now)
	err := s.db.QueryRowContext(ctx, `SELECT
		COALESCE(SUM(kind IN ('root','intermediate')), 0),
		COALESCE(SUM(kind NOT IN ('root','intermediate') AND revoked_at IS NULL AND not_after > ?), 0),
		COALESCE(SUM(kind NOT IN ('root','intermediate') AND revoked_at IS NOT NULL), 0),
		COALESCE(SUM(kind NOT IN ('root','intermediate') AND revoked_at IS NULL AND not_after <= ?), 0),
		COALESCE(SUM(revoked_at IS NULL AND revoke_at IS NOT NULL), 0)
		FROM certificates`, n, n).Scan(&st.CAs, &st.Valid, &st.Revoked, &st.Expired, &st.Scheduled)
	if err != nil {
		return st, fmt.Errorf("store: stats: %w", err)
	}
	return st, nil
}

// RevokeTx marks a certificate revoked now (or at a past time). Already-revoked
// certs are left untouched and ErrNotFound is returned.
func (s *Store) RevokeTx(ctx context.Context, tx *sql.Tx, id int64, at time.Time, reason int) error {
	res, err := tx.ExecContext(ctx, `UPDATE certificates SET revoked_at = ?, revoke_at = NULL, revocation_reason = ?
		WHERE id = ? AND revoked_at IS NULL`, Fmt(at), reason, id)
	if err != nil {
		return fmt.Errorf("store: revoke: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// ScheduleRevoke sets a future revocation time.
func (s *Store) ScheduleRevoke(ctx context.Context, id int64, at time.Time, reason int) error {
	return s.execOne(ctx, `UPDATE certificates SET revoke_at = ?, revocation_reason = ? WHERE id = ? AND revoked_at IS NULL`, Fmt(at), reason, id)
}

// CancelScheduledRevoke removes a scheduled revocation.
func (s *Store) CancelScheduledRevoke(ctx context.Context, id int64) error {
	return s.execOne(ctx, `UPDATE certificates SET revoke_at = NULL, revocation_reason = NULL WHERE id = ? AND revoked_at IS NULL AND revoke_at IS NOT NULL`, id)
}

// DueRevocation is a scheduled revocation whose time has come.
type DueRevocation struct {
	ID, IssuerID int64
	At           time.Time
	CommonName   string
}

// ApplyDueRevocations turns scheduled revocations at or before now into real
// ones, returning what changed.
func (s *Store) ApplyDueRevocations(ctx context.Context, now time.Time) ([]DueRevocation, error) {
	var out []DueRevocation
	err := s.Tx(ctx, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `SELECT id, COALESCE(issuer_id, 0), revoke_at, common_name FROM certificates
			WHERE revoked_at IS NULL AND revoke_at IS NOT NULL AND revoke_at <= ?`, Fmt(now))
		if err != nil {
			return err
		}
		for rows.Next() {
			var d DueRevocation
			var at string
			if err := rows.Scan(&d.ID, &d.IssuerID, &at, &d.CommonName); err != nil {
				_ = rows.Close()
				return err
			}
			d.At = Parse(at)
			out = append(out, d)
		}
		_ = rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, d := range out {
			if _, err := tx.ExecContext(ctx, `UPDATE certificates SET revoked_at = revoke_at, revoke_at = NULL WHERE id = ?`, d.ID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("store: apply revocations: %w", err)
	}
	return out, nil
}

// RevokedEntry is a revoked serial for a CRL.
type RevokedEntry struct {
	Serial    string
	RevokedAt time.Time
	Reason    int
}

// RevokedByIssuer lists revoked, unexpired certs issued by a CA.
func (s *Store) RevokedByIssuer(ctx context.Context, caID int64, now time.Time) ([]RevokedEntry, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT serial, revoked_at, COALESCE(revocation_reason, 0) FROM certificates
		WHERE issuer_id = ? AND revoked_at IS NOT NULL AND not_after > ? ORDER BY id`, caID, Fmt(now))
	if err != nil {
		return nil, fmt.Errorf("store: revoked list: %w", err)
	}
	defer rows.Close()
	var out []RevokedEntry
	for rows.Next() {
		var e RevokedEntry
		var at string
		if err := rows.Scan(&e.Serial, &at, &e.Reason); err != nil {
			return nil, err
		}
		e.RevokedAt = Parse(at)
		out = append(out, e)
	}
	return out, rows.Err()
}

// CAIDs lists every CA with a stored key (they can publish CRLs).
func (s *Store) CAIDs(ctx context.Context) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM certificates WHERE kind IN ('root','intermediate') AND key_enc IS NOT NULL ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("store: list CA ids: %w", err)
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ---- CRLs ----

// CRL is a published revocation list.
type CRL struct {
	CAID       int64
	Number     int64
	ThisUpdate time.Time
	NextUpdate time.Time
	DER        []byte
}

// CRLByCA returns the current CRL for a CA.
func (s *Store) CRLByCA(ctx context.Context, caID int64) (*CRL, error) {
	var c CRL
	var tu, nu string
	err := s.db.QueryRowContext(ctx, `SELECT ca_id, number, this_update, next_update, der FROM crls WHERE ca_id = ?`, caID).
		Scan(&c.CAID, &c.Number, &tu, &nu, &c.DER)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: get CRL: %w", err)
	}
	c.ThisUpdate, c.NextUpdate = Parse(tu), Parse(nu)
	return &c, nil
}

// SaveCRL atomically reserves the next CRL number, calls build with it, and
// stores the result.
func (s *Store) SaveCRL(ctx context.Context, caID int64, build func(number int64) (der []byte, this, next time.Time, err error)) error {
	return s.Tx(ctx, func(tx *sql.Tx) error {
		var cur int64
		err := tx.QueryRowContext(ctx, `SELECT number FROM crls WHERE ca_id = ?`, caID).Scan(&cur)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("store: CRL number: %w", err)
		}
		der, this, next, err := build(cur + 1)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO crls (ca_id, number, this_update, next_update, der) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(ca_id) DO UPDATE SET number = excluded.number, this_update = excluded.this_update,
			next_update = excluded.next_update, der = excluded.der`, caID, cur+1, Fmt(this), Fmt(next), der)
		if err != nil {
			return fmt.Errorf("store: save CRL: %w", err)
		}
		return nil
	})
}

// ---- audit ----

// AuditEntry is one audit log row.
type AuditEntry struct {
	ID       int64
	At       time.Time
	Actor    string
	Action   string
	TargetID sql.NullInt64
	Detail   string
	RemoteIP string
}

// Audit appends to the audit log.
func (s *Store) Audit(ctx context.Context, e AuditEntry) error {
	var target any
	if e.TargetID.Valid {
		target = e.TargetID.Int64
	}
	at := e.At
	if at.IsZero() {
		at = time.Now()
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_log (at, actor, action, target_id, detail, remote_ip) VALUES (?, ?, ?, ?, ?, ?)`,
		Fmt(at), e.Actor, e.Action, target, e.Detail, e.RemoteIP)
	if err != nil {
		return fmt.Errorf("store: audit: %w", err)
	}
	return nil
}

// ListAudit lists audit entries, newest first.
func (s *Store) ListAudit(ctx context.Context, targetID int64, limit, offset int) ([]AuditEntry, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT id, at, actor, action, target_id, detail, remote_ip FROM audit_log`
	var args []any
	if targetID > 0 {
		q += ` WHERE target_id = ?`
		args = append(args, targetID)
	}
	q += ` ORDER BY id DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list audit: %w", err)
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var at string
		if err := rows.Scan(&e.ID, &at, &e.Actor, &e.Action, &e.TargetID, &e.Detail, &e.RemoteIP); err != nil {
			return nil, err
		}
		e.At = Parse(at)
		out = append(out, e)
	}
	return out, rows.Err()
}
