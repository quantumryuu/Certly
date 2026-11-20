package pki

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/youmark/pkcs8"
	"software.sslmate.com/src/go-pkcs12"
)

const day = 24 * time.Hour

type chain struct {
	root, inter *Signer
}

func signer(t *testing.T, is *Issued) *Signer {
	t.Helper()
	return &Signer{Cert: is.Cert, Key: is.Key}
}

func newChain(t *testing.T) chain {
	t.Helper()
	root, err := Issue(Request{Kind: KindRoot, Subject: Subject{CommonName: "Test Root"}, KeyType: KeyECDSAP256, Validity: 3650 * day, PathLen: 1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := Issue(Request{Kind: KindIntermediate, Subject: Subject{CommonName: "Test Intermediate"}, KeyType: KeyECDSAP256, Validity: 1825 * day, PathLen: 0, CRLURL: "http://ca.test/crl/1.crl"}, signer(t, root))
	if err != nil {
		t.Fatal(err)
	}
	return chain{signer(t, root), signer(t, inter)}
}

func (c chain) verify(t *testing.T, leaf *x509.Certificate, usage x509.ExtKeyUsage) error {
	t.Helper()
	roots, inters := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(c.root.Cert)
	inters.AddCert(c.inter.Cert)
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inters, KeyUsages: []x509.ExtKeyUsage{usage}})
	return err
}

func TestIssueChainAndUsages(t *testing.T) {
	c := newChain(t)
	if !c.root.Cert.IsCA || c.root.Cert.MaxPathLen != 1 {
		t.Fatalf("root: IsCA=%v pathlen=%d", c.root.Cert.IsCA, c.root.Cert.MaxPathLen)
	}
	if !c.inter.Cert.MaxPathLenZero {
		t.Fatal("intermediate should have pathlen 0")
	}

	tests := []struct {
		kind      Kind
		key       KeyType
		sans      SANs
		okUsage   []x509.ExtKeyUsage
		failUsage []x509.ExtKeyUsage
	}{
		{KindClient, KeyECDSAP256, SANs{}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}},
		{KindServer, KeyRSA2048, SANs{DNSNames: []string{"svc.lan", "*.svc.lan"}, IPs: []net.IP{net.ParseIP("10.0.0.5")}}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}},
		{KindClientServer, KeyEd25519, SANs{DNSNames: []string{"both.lan"}}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, nil},
		{KindClient, KeyECDSAP384, SANs{Emails: []string{"me@example.com"}}, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil},
	}
	for _, tc := range tests {
		t.Run(string(tc.kind)+"/"+string(tc.key), func(t *testing.T) {
			is, err := Issue(Request{Kind: tc.kind, Subject: Subject{CommonName: "leaf"}, SANs: tc.sans, KeyType: tc.key, Validity: 90 * day, CRLURL: "http://ca.test/crl/2.crl"}, c.inter)
			if err != nil {
				t.Fatal(err)
			}
			if is.Cert.IsCA {
				t.Fatal("leaf is a CA")
			}
			if is.Cert.SerialNumber.Sign() <= 0 || is.Cert.SerialNumber.BitLen() < 127 {
				t.Fatalf("weak serial %x", is.Cert.SerialNumber)
			}
			if got := is.Cert.CRLDistributionPoints; len(got) != 1 || got[0] != "http://ca.test/crl/2.crl" {
				t.Fatalf("CDP = %v", got)
			}
			if !KeyMatchesCert(is.Key, is.Cert) {
				t.Fatal("key does not match cert")
			}
			if KindOf(is.Cert) != tc.kind {
				t.Fatalf("KindOf = %s", KindOf(is.Cert))
			}
			for _, u := range tc.okUsage {
				if err := c.verify(t, is.Cert, u); err != nil {
					t.Fatalf("verify %v: %v", u, err)
				}
			}
			for _, u := range tc.failUsage {
				if err := c.verify(t, is.Cert, u); err == nil {
					t.Fatalf("verify %v should fail", u)
				}
			}
		})
	}
}

func TestIssueRejects(t *testing.T) {
	c := newChain(t)
	tests := []struct {
		name   string
		req    Request
		issuer *Signer
	}{
		{"no CN", Request{Kind: KindClient, KeyType: KeyECDSAP256, Validity: day}, c.inter},
		{"server without SAN", Request{Kind: KindServer, Subject: Subject{CommonName: "x"}, KeyType: KeyECDSAP256, Validity: day}, c.inter},
		{"bad dns", Request{Kind: KindServer, Subject: Subject{CommonName: "x"}, SANs: SANs{DNSNames: []string{"a..b"}}, KeyType: KeyECDSAP256, Validity: day}, c.inter},
		{"outlives issuer", Request{Kind: KindClient, Subject: Subject{CommonName: "x"}, KeyType: KeyECDSAP256, Validity: 3000 * day}, c.inter},
		{"leaf as issuer", Request{Kind: KindClient, Subject: Subject{CommonName: "x"}, KeyType: KeyECDSAP256, Validity: day}, leafSigner(t, c)},
		{"intermediate under pathlen 0", Request{Kind: KindIntermediate, Subject: Subject{CommonName: "x"}, KeyType: KeyECDSAP256, Validity: day}, c.inter},
		{"root with issuer", Request{Kind: KindRoot, Subject: Subject{CommonName: "x"}, KeyType: KeyECDSAP256, Validity: day}, c.root},
		{"leaf without issuer", Request{Kind: KindClient, Subject: Subject{CommonName: "x"}, KeyType: KeyECDSAP256, Validity: day}, nil},
		{"bad key type", Request{Kind: KindClient, Subject: Subject{CommonName: "x"}, KeyType: "rsa-1024", Validity: day}, c.inter},
		{"too long", Request{Kind: KindClient, Subject: Subject{CommonName: "x"}, KeyType: KeyECDSAP256, Validity: 4000 * day}, c.inter},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Issue(tc.req, tc.issuer); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func leafSigner(t *testing.T, c chain) *Signer {
	is, err := Issue(Request{Kind: KindClient, Subject: Subject{CommonName: "leaf"}, KeyType: KeyECDSAP256, Validity: day}, c.inter)
	if err != nil {
		t.Fatal(err)
	}
	return &Signer{Cert: is.Cert, Key: is.Key}
}

func TestSignCSR(t *testing.T) {
	c := newChain(t)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	// The CSR asks for a different CN and a SAN; both must be ignored.
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "evil"}, DNSNames: []string{"evil.com"}}, k)
	csr, err := ParseCSR(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	if err != nil {
		t.Fatal(err)
	}
	is, err := Issue(Request{Kind: KindClient, Subject: Subject{CommonName: "device"}, PublicKey: csr.PublicKey, Validity: 30 * day}, c.inter)
	if err != nil {
		t.Fatal(err)
	}
	if is.Key != nil || is.Cert.Subject.CommonName != "device" || len(is.Cert.DNSNames) != 0 {
		t.Fatalf("CSR fields leaked: %+v", is.Cert.Subject)
	}
	if !KeyMatchesCert(k, is.Cert) {
		t.Fatal("cert not bound to CSR key")
	}

	weak, _ := rsa.GenerateKey(rand.Reader, 1024)
	der, _ = x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "weak"}}, weak)
	if _, err := ParseCSR(der); err == nil {
		t.Fatal("accepted 1024-bit RSA CSR")
	}
	der[len(der)-1] ^= 1
	if _, err := ParseCSR(der); err == nil {
		t.Fatal("accepted CSR with bad signature")
	}
}

func TestCRL(t *testing.T) {
	c := newChain(t)
	now := time.Now()
	entries := []Revoked{
		{Serial: big.NewInt(42), RevokedAt: now.Add(-time.Hour), Reason: ReasonKeyCompromise},
		{Serial: big.NewInt(43), RevokedAt: now, Reason: ReasonUnspecified},
	}
	der, err := BuildCRL(c.inter, entries, 7, now, 7*day)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(c.inter.Cert); err != nil {
		t.Fatalf("CRL signature: %v", err)
	}
	if err := crl.CheckSignatureFrom(c.root.Cert); err == nil {
		t.Fatal("CRL verified against the wrong CA")
	}
	if crl.Number.Int64() != 7 || len(crl.RevokedCertificateEntries) != 2 {
		t.Fatalf("number=%v entries=%d", crl.Number, len(crl.RevokedCertificateEntries))
	}
	if crl.RevokedCertificateEntries[0].ReasonCode != ReasonKeyCompromise {
		t.Fatalf("reason = %d", crl.RevokedCertificateEntries[0].ReasonCode)
	}
	if got := crl.NextUpdate.Sub(crl.ThisUpdate); got < 7*day-time.Second || got > 7*day+time.Second {
		t.Fatalf("validity %v", got)
	}
	if _, err := BuildCRL(leafSigner(t, c), nil, 1, now, day); err == nil {
		t.Fatal("leaf signed a CRL")
	}
}

func TestExports(t *testing.T) {
	c := newChain(t)
	leaf, err := Issue(Request{Kind: KindClient, Subject: Subject{CommonName: "My Laptop/../x"}, KeyType: KeyECDSAP256, Validity: 30 * day}, c.inter)
	if err != nil {
		t.Fatal(err)
	}
	b := Bundle{Cert: leaf.Cert, Chain: []*x509.Certificate{c.inter.Cert, c.root.Cert}, Key: leaf.Key}
	const pw = "correct horse"

	t.Run("names are safe", func(t *testing.T) {
		f, _ := Export(b, "cert-pem", ExportOptions{})
		if strings.ContainsAny(f.Name, "/\\ ") || strings.Contains(f.Name, "..") {
			t.Fatalf("unsafe name %q", f.Name)
		}
	})
	t.Run("pem formats", func(t *testing.T) {
		for id, n := range map[string]int{"cert-pem": 1, "chain-pem": 2, "fullchain-pem": 3} {
			f, err := Export(b, id, ExportOptions{})
			if err != nil {
				t.Fatal(err)
			}
			certs, err := ParseCertificates(f.Data)
			if err != nil || len(certs) != n {
				t.Fatalf("%s: %d certs, %v", id, len(certs), err)
			}
		}
		f, _ := Export(b, "cert-der", ExportOptions{})
		if _, err := x509.ParseCertificate(f.Data); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("plain key", func(t *testing.T) {
		f, err := Export(b, "key-pem", ExportOptions{})
		if err != nil {
			t.Fatal(err)
		}
		k, err := ParsePrivateKey(f.Data, nil)
		if err != nil || !KeyMatchesCert(k, leaf.Cert) {
			t.Fatalf("plain key: %v", err)
		}
	})
	t.Run("encrypted key", func(t *testing.T) {
		f, err := Export(b, "key-pem", ExportOptions{Password: pw})
		if err != nil {
			t.Fatal(err)
		}
		blk, _ := pem.Decode(f.Data)
		if blk.Type != "ENCRYPTED PRIVATE KEY" {
			t.Fatalf("type %s", blk.Type)
		}
		if _, _, err := pkcs8.ParsePrivateKey(blk.Bytes, []byte("wrong password")); err == nil {
			t.Fatal("decrypted with wrong password")
		}
		k, err := ParsePrivateKey(f.Data, []byte(pw))
		if err != nil || !KeyMatchesCert(k, leaf.Cert) {
			t.Fatalf("decrypt: %v", err)
		}
	})
	t.Run("p12", func(t *testing.T) {
		if _, err := Export(b, "p12", ExportOptions{}); err == nil {
			t.Fatal("p12 without password")
		}
		f, err := Export(b, "p12", ExportOptions{Password: pw})
		if err != nil {
			t.Fatal(err)
		}
		key, cert, cas, err := pkcs12.DecodeChain(f.Data, pw)
		if err != nil {
			t.Fatal(err)
		}
		if !cert.Equal(leaf.Cert) || len(cas) != 2 || !KeyMatchesCert(key.(*ecdsa.PrivateKey), leaf.Cert) {
			t.Fatal("p12 contents mismatch")
		}
		if _, _, _, err := pkcs12.DecodeChain(f.Data, "nope nope"); err == nil {
			t.Fatal("p12 opened with wrong password")
		}
	})
	t.Run("zip", func(t *testing.T) {
		f, err := Export(b, "zip", ExportOptions{IncludeKey: true, Password: pw})
		if err != nil {
			t.Fatal(err)
		}
		zr, err := zip.NewReader(bytes.NewReader(f.Data), int64(len(f.Data)))
		if err != nil {
			t.Fatal(err)
		}
		names := map[string][]byte{}
		for _, zf := range zr.File {
			if strings.Contains(zf.Name, "..") || strings.HasPrefix(zf.Name, "/") {
				t.Fatalf("unsafe zip entry %q", zf.Name)
			}
			rc, _ := zf.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			names[zf.Name[strings.Index(zf.Name, "/")+1:]] = data
		}
		for _, want := range []string{"cert.pem", "chain.pem", "fullchain.pem", "ca.pem", "key.pem", "bundle.p12", "README.txt"} {
			if _, ok := names[want]; !ok {
				t.Fatalf("zip missing %s (have %v)", want, names)
			}
		}
		if !bytes.Contains(names["key.pem"], []byte("ENCRYPTED PRIVATE KEY")) {
			t.Fatal("zip key not encrypted")
		}
		noKey, _ := Export(b, "zip", ExportOptions{})
		if bytes.Contains(noKey.Data, []byte("key.pem")) {
			t.Fatal("zip contains key when not requested")
		}
	})
	t.Run("rules", func(t *testing.T) {
		if _, err := Export(b, "key-pem", ExportOptions{Password: "short"}); err == nil {
			t.Fatal("accepted short password")
		}
		caBundle := Bundle{Cert: c.inter.Cert, Chain: []*x509.Certificate{c.root.Cert}, Key: c.inter.Key}
		if _, err := Export(caBundle, "key-pem", ExportOptions{}); err == nil {
			t.Fatal("exported CA key without a password")
		}
		if _, err := Export(Bundle{Cert: leaf.Cert}, "key-pem", ExportOptions{}); err == nil {
			t.Fatal("exported key that doesn't exist")
		}
		if _, err := Export(b, "bogus", ExportOptions{}); err == nil {
			t.Fatal("unknown format accepted")
		}
	})
}

func TestParsePrivateKeyRejectsLegacy(t *testing.T) {
	legacy := "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00000000000000000000000000000000\n\nAAAA\n-----END RSA PRIVATE KEY-----\n"
	if _, err := ParsePrivateKey([]byte(legacy), []byte("x")); err == nil {
		t.Fatal("accepted legacy encrypted PEM")
	}
}
