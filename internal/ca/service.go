// Package ca ties pki, store and crypto together: it issues, revokes,
// exports and imports certificates, keeps CRLs current, and writes the audit
// log. The web UI, CLI and background jobs all go through it.
package ca

import (
	"context"
	"crypto"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strconv"
	"strings"
	"time"

	certcrypto "github.com/quantumryuu/Certly/internal/crypto"
	"github.com/quantumryuu/Certly/internal/pki"
	"github.com/quantumryuu/Certly/internal/store"
)

// maxChainDepth guards against loops in issuer links.
const maxChainDepth = 8

// Service is the CA application service.
type Service struct {
	Store       *store.Store
	Env         *certcrypto.Envelope
	BaseURL     string        // e.g. https://certly.lan, no trailing slash
	CRLValidity time.Duration // how long a CRL is valid
	Log         *slog.Logger
	Now         func() time.Time
}

// Actor is who performs an action, for the audit log.
type Actor struct {
	Name string
	IP   string
}

// System is the actor for background jobs.
var System = Actor{Name: "system"}

// UserError is an error that is safe to show to the user.
type UserError struct{ Msg string }

func (e *UserError) Error() string { return e.Msg }

func userErr(format string, a ...any) error { return &UserError{Msg: fmt.Sprintf(format, a...)} }

// ErrNotFound means the certificate doesn't exist.
var ErrNotFound = store.ErrNotFound

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) audit(ctx context.Context, a Actor, action string, target int64, detail string) {
	e := store.AuditEntry{Actor: a.Name, Action: action, Detail: detail, RemoteIP: a.IP}
	if target > 0 {
		e.TargetID = sql.NullInt64{Int64: target, Valid: true}
	}
	if err := s.Store.Audit(ctx, e); err != nil && s.Log != nil {
		s.Log.Error("audit log write failed", "action", action, "err", err)
	}
}

// Audit records an action that happens outside the service (login, backup...).
func (s *Service) Audit(ctx context.Context, a Actor, action string, target int64, detail string) {
	s.audit(ctx, a, action, target, detail)
}

func keyAAD(id int64) string { return "cert-key:" + strconv.FormatInt(id, 10) }

// CRLURL is the public CRL address for a CA.
func (s *Service) CRLURL(caID int64) string {
	return strings.TrimRight(s.BaseURL, "/") + "/crl/" + strconv.FormatInt(caID, 10) + ".crl"
}

// Signer loads a CA with its decrypted key.
func (s *Service) signer(ctx context.Context, id int64) (*pki.Signer, *store.Cert, error) {
	c, err := s.Store.CertByID(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if !c.IsCA() {
		return nil, nil, userErr("certificate %d is not a CA", id)
	}
	if !c.HasKey() {
		return nil, nil, userErr("no private key is stored for CA %q", c.CommonName)
	}
	cert, err := x509.ParseCertificate(c.DER)
	if err != nil {
		return nil, nil, fmt.Errorf("ca: parse stored cert %d: %w", id, err)
	}
	key, err := s.loadKey(c)
	if err != nil {
		return nil, nil, err
	}
	return &pki.Signer{Cert: cert, Key: key}, c, nil
}

func (s *Service) loadKey(c *store.Cert) (crypto.Signer, error) {
	der, err := s.Env.Open(c.KeyEnc, keyAAD(c.ID))
	if err != nil {
		// Don't wrap: never hint at key material in errors.
		return nil, fmt.Errorf("ca: unable to decrypt key for certificate %d (wrong master key?)", c.ID)
	}
	defer clear(der)
	return pki.UnmarshalKey(der)
}

// Chain returns the issuer chain for a cert: issuer first, root last.
func (s *Service) Chain(ctx context.Context, c *store.Cert) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	cur := c
	for i := 0; cur.IssuerID.Valid; i++ {
		if i >= maxChainDepth {
			return nil, errors.New("ca: issuer chain too deep or looping")
		}
		parent, err := s.Store.CertByID(ctx, cur.IssuerID.Int64)
		if err != nil {
			return nil, fmt.Errorf("ca: load issuer: %w", err)
		}
		pc, err := x509.ParseCertificate(parent.DER)
		if err != nil {
			return nil, fmt.Errorf("ca: parse issuer: %w", err)
		}
		out = append(out, pc)
		cur = parent
	}
	return out, nil
}

// IssueInput describes a certificate to create.
type IssueInput struct {
	Request  pki.Request
	IssuerID int64 // 0 for a root CA
	Notes    string
}

// Issue creates a CA or leaf certificate and stores it with its encrypted key.
func (s *Service) Issue(ctx context.Context, a Actor, in IssueInput) (*store.Cert, error) {
	req := in.Request
	req.Now = s.now()
	var issuer *pki.Signer
	if req.Kind == pki.KindRoot {
		if in.IssuerID != 0 {
			return nil, userErr("a root CA can't have an issuer")
		}
	} else {
		if in.IssuerID == 0 {
			return nil, userErr("choose an issuing CA")
		}
		sig, ic, err := s.signer(ctx, in.IssuerID)
		if errors.Is(err, store.ErrNotFound) {
			return nil, userErr("issuing CA not found")
		}
		if err != nil {
			return nil, err
		}
		if !ic.Usable(req.Now) {
			return nil, userErr("CA %q is %s and can't issue certificates", ic.CommonName, ic.Status(req.Now))
		}
		if err := s.checkChain(ctx, ic, req.Now); err != nil {
			return nil, err
		}
		issuer = sig
		req.CRLURL = s.CRLURL(in.IssuerID)
	}

	is, err := pki.Issue(req, issuer)
	if err != nil {
		return nil, &UserError{Msg: strings.TrimPrefix(err.Error(), "pki: ")}
	}
	kt, err := pki.KeyTypeOf(is.Cert.PublicKey)
	if err != nil {
		return nil, err
	}
	row := &store.Cert{
		Kind: string(req.Kind), CommonName: is.Cert.Subject.CommonName, Subject: is.Cert.Subject.String(),
		Serial: serialHex(is.Cert.SerialNumber), KeyType: string(kt),
		NotBefore: is.Cert.NotBefore, NotAfter: is.Cert.NotAfter, SANs: sanString(is.Cert), DER: is.DER,
		Notes: strings.TrimSpace(in.Notes),
	}
	if in.IssuerID != 0 {
		row.IssuerID = sql.NullInt64{Int64: in.IssuerID, Valid: true}
	}
	id, err := s.insert(ctx, row, is.Key)
	if err != nil {
		return nil, err
	}
	detail := fmt.Sprintf("kind=%s cn=%q serial=%s key=%s", req.Kind, row.CommonName, row.Serial, kt)
	if is.Key == nil {
		detail += " from=csr"
	}
	s.audit(ctx, a, "issue", id, detail)

	if req.Kind.IsCA() {
		// Publish an (empty) CRL right away so the URL in issued certs works.
		if err := s.RegenerateCRL(ctx, id); err != nil {
			return nil, err
		}
	}
	return s.Store.CertByID(ctx, id)
}

// checkChain refuses to issue when any CA above the issuer is revoked or expired.
func (s *Service) checkChain(ctx context.Context, issuer *store.Cert, now time.Time) error {
	cur := issuer
	for i := 0; cur.IssuerID.Valid; i++ {
		if i >= maxChainDepth {
			return errors.New("ca: issuer chain too deep or looping")
		}
		parent, err := s.Store.CertByID(ctx, cur.IssuerID.Int64)
		if err != nil {
			return fmt.Errorf("ca: load issuer chain: %w", err)
		}
		if st := parent.Status(now); st == "revoked" || st == "expired" {
			return userErr("CA %q higher up the chain is %s; certificates issued now would not validate", parent.CommonName, st)
		}
		cur = parent
	}
	return nil
}

// insert stores a cert row and seals its key (if any) bound to the row id.
func (s *Service) insert(ctx context.Context, row *store.Cert, key crypto.Signer) (int64, error) {
	var id int64
	err := s.Store.Tx(ctx, func(tx *sql.Tx) error {
		var err error
		id, err = s.Store.InsertCertTx(ctx, tx, row)
		if err != nil {
			return err
		}
		if key == nil {
			return nil
		}
		der, err := pki.MarshalKey(key)
		if err != nil {
			return err
		}
		defer clear(der)
		sealed, err := s.Env.Seal(der, keyAAD(id))
		if err != nil {
			return err
		}
		return s.Store.SetCertKeyTx(ctx, tx, id, sealed)
	})
	return id, err
}

func serialHex(n *big.Int) string { return strings.ToUpper(n.Text(16)) }

func sanString(c *x509.Certificate) string {
	var parts []string
	parts = append(parts, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		parts = append(parts, ip.String())
	}
	parts = append(parts, c.EmailAddresses...)
	for _, u := range c.URIs {
		parts = append(parts, u.String())
	}
	return strings.Join(parts, ", ")
}

// Export encodes a certificate for download and audits it.
func (s *Service) Export(ctx context.Context, a Actor, id int64, format string, opt pki.ExportOptions) (*pki.File, error) {
	c, err := s.Store.CertByID(ctx, id)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(c.DER)
	if err != nil {
		return nil, fmt.Errorf("ca: parse stored cert: %w", err)
	}
	chain, err := s.Chain(ctx, c)
	if err != nil {
		return nil, err
	}
	b := pki.Bundle{Cert: cert, Chain: chain}
	f, ok := pki.FormatByID(format)
	if !ok {
		return nil, userErr("unknown export format")
	}
	withKey := f.NeedsKey || (format == "zip" && opt.IncludeKey)
	if withKey {
		if !c.HasKey() {
			return nil, userErr("no private key is stored for this certificate")
		}
		if b.Key, err = s.loadKey(c); err != nil {
			return nil, err
		}
	}
	file, err := pki.Export(b, format, opt)
	if err != nil {
		return nil, &UserError{Msg: strings.TrimPrefix(err.Error(), "pki: ")}
	}
	s.audit(ctx, a, "export", id, fmt.Sprintf("format=%s key=%t password=%t", format, withKey, opt.Password != ""))
	return file, nil
}

// Revoke revokes a certificate now, or schedules it when at is in the future.
func (s *Service) Revoke(ctx context.Context, a Actor, id int64, at time.Time, reason int) error {
	if !pki.ValidReason(reason) {
		return userErr("invalid revocation reason")
	}
	c, err := s.Store.CertByID(ctx, id)
	if err != nil {
		return err
	}
	if c.RevokedAt != nil {
		return userErr("certificate is already revoked")
	}
	now := s.now()
	if at.IsZero() || !at.After(now) {
		if at.IsZero() || at.Before(c.NotBefore) {
			at = now
		}
		err := s.Store.Tx(ctx, func(tx *sql.Tx) error { return s.Store.RevokeTx(ctx, tx, id, at, reason) })
		if err != nil {
			return err
		}
		s.audit(ctx, a, "revoke", id, fmt.Sprintf("cn=%q serial=%s reason=%s", c.CommonName, c.Serial, pki.ReasonLabel(reason)))
		if c.IssuerID.Valid {
			return s.RegenerateCRL(ctx, c.IssuerID.Int64)
		}
		return nil
	}
	if at.After(c.NotAfter) {
		return userErr("the certificate expires before that date anyway (%s)", c.NotAfter.Format(time.DateOnly))
	}
	if err := s.Store.ScheduleRevoke(ctx, id, at, reason); err != nil {
		return err
	}
	s.audit(ctx, a, "schedule-revoke", id, fmt.Sprintf("cn=%q at=%s reason=%s", c.CommonName, store.Fmt(at), pki.ReasonLabel(reason)))
	return nil
}

// CancelRevoke removes a scheduled revocation.
func (s *Service) CancelRevoke(ctx context.Context, a Actor, id int64) error {
	if err := s.Store.CancelScheduledRevoke(ctx, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return userErr("no scheduled revocation to cancel")
		}
		return err
	}
	s.audit(ctx, a, "cancel-revoke", id, "")
	return nil
}

// ApplyScheduled turns due scheduled revocations into real ones.
func (s *Service) ApplyScheduled(ctx context.Context) (int, error) {
	due, err := s.Store.ApplyDueRevocations(ctx, s.now())
	if err != nil {
		return 0, err
	}
	issuers := map[int64]bool{}
	for _, d := range due {
		s.audit(ctx, System, "revoke", d.ID, fmt.Sprintf("cn=%q scheduled=%s", d.CommonName, store.Fmt(d.At)))
		if d.IssuerID > 0 {
			issuers[d.IssuerID] = true
		}
	}
	var errs []error
	for id := range issuers {
		if err := s.RegenerateCRL(ctx, id); err != nil {
			errs = append(errs, err)
		}
	}
	return len(due), errors.Join(errs...)
}

// RegenerateCRL signs and stores a fresh CRL for a CA. Revoked or expired CAs
// keep their last CRL.
func (s *Service) RegenerateCRL(ctx context.Context, caID int64) error {
	sig, c, err := s.signer(ctx, caID)
	if err != nil {
		var ue *UserError
		if errors.As(err, &ue) {
			return nil // imported CA without key: nothing to sign with
		}
		return err
	}
	now := s.now()
	if !c.Usable(now) {
		return nil
	}
	entries, err := s.Store.RevokedByIssuer(ctx, caID, now)
	if err != nil {
		return err
	}
	revoked := make([]pki.Revoked, 0, len(entries))
	for _, e := range entries {
		n, ok := new(big.Int).SetString(e.Serial, 16)
		if !ok {
			return fmt.Errorf("ca: bad stored serial %q", e.Serial)
		}
		revoked = append(revoked, pki.Revoked{Serial: n, RevokedAt: e.RevokedAt, Reason: e.Reason})
	}
	return s.Store.SaveCRL(ctx, caID, func(number int64) ([]byte, time.Time, time.Time, error) {
		der, err := pki.BuildCRL(sig, revoked, number, now, s.CRLValidity)
		if err != nil {
			return nil, now, now, err
		}
		parsed, err := x509.ParseRevocationList(der)
		if err != nil {
			return nil, now, now, err
		}
		return der, parsed.ThisUpdate, parsed.NextUpdate, nil
	})
}

// RefreshCRLs regenerates CRLs that are missing or past half their validity.
func (s *Service) RefreshCRLs(ctx context.Context) error {
	ids, err := s.Store.CAIDs(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	var errs []error
	for _, id := range ids {
		crl, err := s.Store.CRLByCA(ctx, id)
		if err == nil && crl.NextUpdate.Sub(now) > s.CRLValidity/2 {
			continue
		}
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			errs = append(errs, err)
			continue
		}
		if err := s.RegenerateCRL(ctx, id); err != nil {
			errs = append(errs, fmt.Errorf("CA %d: %w", id, err))
		}
	}
	return errors.Join(errs...)
}

// CRL returns the DER CRL for a CA, generating it on first use.
func (s *Service) CRL(ctx context.Context, caID int64) ([]byte, error) {
	crl, err := s.Store.CRLByCA(ctx, caID)
	if errors.Is(err, store.ErrNotFound) {
		if err := s.RegenerateCRL(ctx, caID); err != nil {
			return nil, err
		}
		crl, err = s.Store.CRLByCA(ctx, caID)
	}
	if err != nil {
		return nil, err
	}
	return crl.DER, nil
}

// Import stores an existing certificate (and optionally its key), e.g. from
// the old scripts. The issuer must already be in Certly unless it's a root.
func (s *Service) Import(ctx context.Context, a Actor, certPEM, keyPEM, keyPassword []byte, notes string) (*store.Cert, error) {
	certs, err := pki.ParseCertificates(certPEM)
	if err != nil {
		return nil, &UserError{Msg: strings.TrimPrefix(err.Error(), "pki: ")}
	}
	cert := certs[0]
	kt, err := pki.KeyTypeOf(cert.PublicKey)
	if err != nil {
		return nil, &UserError{Msg: strings.TrimPrefix(err.Error(), "pki: ")}
	}
	if isWeakSig(cert.SignatureAlgorithm) {
		return nil, userErr("certificate uses a weak signature algorithm (%s)", cert.SignatureAlgorithm)
	}
	var key crypto.Signer
	if len(keyPEM) > 0 {
		key, err = pki.ParsePrivateKey(keyPEM, keyPassword)
		if err != nil {
			return nil, &UserError{Msg: strings.TrimPrefix(err.Error(), "pki: ")}
		}
		if !pki.KeyMatchesCert(key, cert) {
			return nil, userErr("the private key does not match the certificate")
		}
	}
	kind := pki.KindOf(cert)
	row := &store.Cert{
		Kind: string(kind), CommonName: cert.Subject.CommonName, Subject: cert.Subject.String(),
		Serial: serialHex(cert.SerialNumber), KeyType: string(kt), NotBefore: cert.NotBefore, NotAfter: cert.NotAfter,
		SANs: sanString(cert), DER: cert.Raw, Notes: strings.TrimSpace(notes), Imported: true,
	}
	if row.CommonName == "" {
		row.CommonName = row.Subject
	}
	if kind != pki.KindRoot {
		issuerID, err := s.findIssuer(ctx, cert)
		if err != nil {
			return nil, err
		}
		row.IssuerID = sql.NullInt64{Int64: issuerID, Valid: true}
	}
	id, err := s.insert(ctx, row, key)
	if err != nil {
		return nil, &UserError{Msg: strings.TrimPrefix(err.Error(), "store: ")}
	}
	s.audit(ctx, a, "import", id, fmt.Sprintf("kind=%s cn=%q serial=%s key=%t", kind, row.CommonName, row.Serial, key != nil))
	if kind.IsCA() && key != nil {
		if err := s.RegenerateCRL(ctx, id); err != nil {
			return nil, err
		}
	}
	return s.Store.CertByID(ctx, id)
}

func isWeakSig(alg x509.SignatureAlgorithm) bool {
	switch alg {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1, x509.UnknownSignatureAlgorithm:
		return true
	}
	return false
}

// findIssuer finds the stored CA that signed cert.
func (s *Service) findIssuer(ctx context.Context, cert *x509.Certificate) (int64, error) {
	cas, err := s.Store.ListCerts(ctx, store.CertFilter{CAs: true}, s.now())
	if err != nil {
		return 0, err
	}
	for _, c := range cas {
		pc, err := x509.ParseCertificate(c.DER)
		if err != nil {
			continue
		}
		if string(pc.RawSubject) == string(cert.RawIssuer) && cert.CheckSignatureFrom(pc) == nil {
			return c.ID, nil
		}
	}
	return 0, userErr("issuer %q is not in Certly; import the issuing CA first", cert.Issuer.String())
}
