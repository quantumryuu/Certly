package ca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"path/filepath"
	"testing"
	"time"

	certcrypto "github.com/quantumryuu/Certly/internal/crypto"
	"github.com/quantumryuu/Certly/internal/pki"
	"github.com/quantumryuu/Certly/internal/store"
)

const day = 24 * time.Hour

var admin = Actor{Name: "admin", IP: "127.0.0.1"}

func newService(t *testing.T) *Service {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "certly.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	env, _ := certcrypto.New(bytes.Repeat([]byte{1}, certcrypto.KeySize))
	return &Service{Store: st, Env: env, BaseURL: "https://certly.test/", CRLValidity: 7 * day}
}

type fixture struct {
	s           *Service
	root, inter *store.Cert
}

func setup(t *testing.T) fixture {
	t.Helper()
	s := newService(t)
	ctx := context.Background()
	root, err := s.Issue(ctx, admin, IssueInput{Request: pki.Request{Kind: pki.KindRoot, Subject: pki.Subject{CommonName: "Root"}, KeyType: pki.KeyECDSAP256, Validity: 3650 * day, PathLen: 1}})
	if err != nil {
		t.Fatal(err)
	}
	inter, err := s.Issue(ctx, admin, IssueInput{IssuerID: root.ID, Request: pki.Request{Kind: pki.KindIntermediate, Subject: pki.Subject{CommonName: "Inter"}, KeyType: pki.KeyECDSAP256, Validity: 1825 * day, PathLen: 0}})
	if err != nil {
		t.Fatal(err)
	}
	return fixture{s, root, inter}
}

func (f fixture) leaf(t *testing.T, cn string) *store.Cert {
	t.Helper()
	c, err := f.s.Issue(context.Background(), admin, IssueInput{IssuerID: f.inter.ID, Request: pki.Request{Kind: pki.KindClient, Subject: pki.Subject{CommonName: cn}, KeyType: pki.KeyECDSAP256, Validity: 90 * day}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func crlSerials(t *testing.T, s *Service, caID int64, issuer *store.Cert) map[string]int {
	t.Helper()
	der, err := s.CRL(context.Background(), caID)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	ic, _ := x509.ParseCertificate(issuer.DER)
	if err := crl.CheckSignatureFrom(ic); err != nil {
		t.Fatalf("CRL signature: %v", err)
	}
	out := map[string]int{}
	for _, e := range crl.RevokedCertificateEntries {
		out[e.SerialNumber.Text(16)] = e.ReasonCode
	}
	return out
}

func lower(s string) string { n, _ := new(big.Int).SetString(s, 16); return n.Text(16) }

func TestIssueStoresEncryptedKeyAndCDP(t *testing.T) {
	f := setup(t)
	c := f.leaf(t, "laptop")
	if !c.HasKey() {
		t.Fatal("no key stored")
	}
	cert, _ := x509.ParseCertificate(c.DER)
	if got := cert.CRLDistributionPoints; len(got) != 1 || got[0] != "https://certly.test/crl/2.crl" {
		t.Fatalf("CDP = %v", got)
	}
	der, _ := pki.MarshalKey(mustKey(t, f.s, c))
	if bytes.Contains(c.KeyEnc, der) {
		t.Fatal("key stored in plaintext")
	}
	// The sealed key is bound to its row: moving it to another cert must fail.
	other := f.leaf(t, "phone")
	other.KeyEnc = c.KeyEnc
	if _, err := f.s.loadKey(other); err == nil {
		t.Fatal("sealed key opened under another row id")
	}
}

func mustKey(t *testing.T, s *Service, c *store.Cert) crypto.Signer {
	t.Helper()
	k, err := s.loadKey(c)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRevokeNowUpdatesCRL(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	c := f.leaf(t, "laptop")
	keep := f.leaf(t, "phone")
	if err := f.s.Revoke(ctx, admin, c.ID, time.Time{}, pki.ReasonKeyCompromise); err != nil {
		t.Fatal(err)
	}
	got := crlSerials(t, f.s, f.inter.ID, f.inter)
	if r, ok := got[lower(c.Serial)]; !ok || r != pki.ReasonKeyCompromise {
		t.Fatalf("revoked serial missing from CRL: %v", got)
	}
	if _, ok := got[lower(keep.Serial)]; ok {
		t.Fatal("unrevoked serial in CRL")
	}
	if err := f.s.Revoke(ctx, admin, c.ID, time.Time{}, 0); err == nil {
		t.Fatal("revoked twice")
	}
	// Revoking the intermediate puts it on the root's CRL and stops it issuing.
	if err := f.s.Revoke(ctx, admin, f.inter.ID, time.Time{}, pki.ReasonCACompromise); err != nil {
		t.Fatal(err)
	}
	if _, ok := crlSerials(t, f.s, f.root.ID, f.root)[lower(f.inter.Serial)]; !ok {
		t.Fatal("intermediate missing from root CRL")
	}
	_, err := f.s.Issue(ctx, admin, IssueInput{IssuerID: f.inter.ID, Request: pki.Request{Kind: pki.KindClient, Subject: pki.Subject{CommonName: "x"}, KeyType: pki.KeyECDSAP256, Validity: day}})
	var ue *UserError
	if !errors.As(err, &ue) {
		t.Fatalf("revoked CA issued a cert: %v", err)
	}
}

func TestRevokedRootBlocksIntermediate(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if err := f.s.Revoke(ctx, admin, f.root.ID, time.Time{}, pki.ReasonCACompromise); err != nil {
		t.Fatal(err)
	}
	_, err := f.s.Issue(ctx, admin, IssueInput{IssuerID: f.inter.ID, Request: pki.Request{Kind: pki.KindClient, Subject: pki.Subject{CommonName: "x"}, KeyType: pki.KeyECDSAP256, Validity: day}})
	var ue *UserError
	if !errors.As(err, &ue) {
		t.Fatalf("intermediate under a revoked root issued a cert: %v", err)
	}
}

func TestScheduledRevocation(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	c := f.leaf(t, "laptop")
	at := time.Now().Add(time.Hour).Truncate(time.Second)
	if err := f.s.Revoke(ctx, admin, c.ID, at, pki.ReasonSuperseded); err != nil {
		t.Fatal(err)
	}
	if n, _ := f.s.ApplyScheduled(ctx); n != 0 {
		t.Fatal("applied before due")
	}
	if _, ok := crlSerials(t, f.s, f.inter.ID, f.inter)[lower(c.Serial)]; ok {
		t.Fatal("scheduled revocation in CRL too early")
	}
	f.s.Now = func() time.Time { return at.Add(time.Minute) }
	if n, err := f.s.ApplyScheduled(ctx); n != 1 || err != nil {
		t.Fatalf("applied %d, %v", n, err)
	}
	if _, ok := crlSerials(t, f.s, f.inter.ID, f.inter)[lower(c.Serial)]; !ok {
		t.Fatal("scheduled revocation not in CRL")
	}
	got, _ := f.s.Store.CertByID(ctx, c.ID)
	if got.RevokedAt == nil || !got.RevokedAt.Equal(at) {
		t.Fatalf("revoked_at = %v, want %v", got.RevokedAt, at)
	}

	other := f.leaf(t, "phone")
	_ = f.s.Revoke(ctx, admin, other.ID, at.Add(48*time.Hour), 0)
	if err := f.s.CancelRevoke(ctx, admin, other.ID); err != nil {
		t.Fatal(err)
	}
	f.s.Now = func() time.Time { return at.Add(72 * time.Hour) }
	if n, _ := f.s.ApplyScheduled(ctx); n != 0 {
		t.Fatal("cancelled revocation was applied")
	}
}

func TestExportAudited(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	c := f.leaf(t, "laptop")
	file, err := f.s.Export(ctx, admin, c.ID, "key-pem", pki.ExportOptions{Password: "longenough"})
	if err != nil {
		t.Fatal(err)
	}
	k, err := pki.ParsePrivateKey(file.Data, []byte("longenough"))
	cert, _ := x509.ParseCertificate(c.DER)
	if err != nil || !pki.KeyMatchesCert(k, cert) {
		t.Fatalf("exported key: %v", err)
	}
	if _, err := f.s.Export(ctx, admin, f.inter.ID, "key-pem", pki.ExportOptions{}); err == nil {
		t.Fatal("CA key exported without password")
	}
	log, _ := f.s.Store.ListAudit(ctx, c.ID, 10, 0)
	if len(log) < 2 || log[0].Action != "export" {
		t.Fatalf("audit = %+v", log)
	}
	if bytes.Contains([]byte(log[0].Detail), []byte("longenough")) {
		t.Fatal("password in audit log")
	}
}

func TestImport(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	// An existing CA from "old scripts".
	oldRoot, _ := pki.Issue(pki.Request{Kind: pki.KindRoot, Subject: pki.Subject{CommonName: "Old Root"}, KeyType: pki.KeyECDSAP256, Validity: 365 * day, PathLen: -1}, nil)
	oldLeaf, _ := pki.Issue(pki.Request{Kind: pki.KindServer, Subject: pki.Subject{CommonName: "nas"}, SANs: pki.SANs{DNSNames: []string{"nas.lan"}}, KeyType: pki.KeyECDSAP256, Validity: 30 * day}, &pki.Signer{Cert: oldRoot.Cert, Key: oldRoot.Key})
	rootKey, _ := pki.KeyPEM(oldRoot.Key, "")

	if _, err := f.s.Import(ctx, admin, pki.CertPEM(oldLeaf.Cert), nil, nil, ""); err == nil {
		t.Fatal("imported leaf without its issuer")
	}
	wrongKey, _ := pki.KeyPEM(oldLeaf.Key, "")
	if _, err := f.s.Import(ctx, admin, pki.CertPEM(oldRoot.Cert), wrongKey, nil, ""); err == nil {
		t.Fatal("imported mismatched key")
	}
	r, err := f.s.Import(ctx, admin, pki.CertPEM(oldRoot.Cert), rootKey, nil, "from scripts")
	if err != nil {
		t.Fatal(err)
	}
	if r.Kind != "root" || !r.HasKey() || !r.Imported {
		t.Fatalf("imported root: %+v", r)
	}
	l, err := f.s.Import(ctx, admin, pki.CertPEM(oldLeaf.Cert), nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if l.Kind != "server" || l.IssuerID.Int64 != r.ID || l.HasKey() {
		t.Fatalf("imported leaf: %+v", l)
	}
	// Revoking an imported cert lands on the imported CA's CRL.
	if err := f.s.Revoke(ctx, admin, l.ID, time.Time{}, 0); err != nil {
		t.Fatal(err)
	}
	if _, ok := crlSerials(t, f.s, r.ID, r)[lower(l.Serial)]; !ok {
		t.Fatal("imported leaf not in CRL")
	}
	if _, err := f.s.Import(ctx, admin, pki.CertPEM(oldLeaf.Cert), nil, nil, ""); err == nil {
		t.Fatal("imported duplicate")
	}
}

func TestSignCSRStoresNoKey(t *testing.T) {
	f := setup(t)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "ignored"}}, k)
	csr, err := pki.ParseCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.s.Issue(context.Background(), admin, IssueInput{IssuerID: f.inter.ID, Request: pki.Request{Kind: pki.KindClient, Subject: pki.Subject{CommonName: "dev"}, PublicKey: csr.PublicKey, Validity: day}})
	if err != nil {
		t.Fatal(err)
	}
	if c.HasKey() {
		t.Fatal("stored a key for a CSR-signed cert")
	}
	if _, err := f.s.Export(context.Background(), admin, c.ID, "p12", pki.ExportOptions{Password: "longenough"}); err == nil {
		t.Fatal("exported p12 without a key")
	}
}

func TestRefreshCRLs(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	before, _ := f.s.Store.CRLByCA(ctx, f.inter.ID)
	if err := f.s.RefreshCRLs(ctx); err != nil {
		t.Fatal(err)
	}
	same, _ := f.s.Store.CRLByCA(ctx, f.inter.ID)
	if same.Number != before.Number {
		t.Fatal("fresh CRL regenerated needlessly")
	}
	f.s.Now = func() time.Time { return time.Now().Add(5 * day) }
	if err := f.s.RefreshCRLs(ctx); err != nil {
		t.Fatal(err)
	}
	after, _ := f.s.Store.CRLByCA(ctx, f.inter.ID)
	if after.Number != before.Number+1 || !after.NextUpdate.After(before.NextUpdate) {
		t.Fatalf("stale CRL not refreshed: %d -> %d", before.Number, after.Number)
	}
}
