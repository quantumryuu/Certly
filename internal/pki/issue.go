package pki

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Kind is what a certificate is for.
type Kind string

// Certificate kinds.
const (
	KindRoot         Kind = "root"
	KindIntermediate Kind = "intermediate"
	KindClient       Kind = "client"
	KindServer       Kind = "server"
	KindClientServer Kind = "client-server"
)

// IsCA reports whether the kind is a CA.
func (k Kind) IsCA() bool { return k == KindRoot || k == KindIntermediate }

// Valid reports whether k is a known kind.
func (k Kind) Valid() bool {
	switch k {
	case KindRoot, KindIntermediate, KindClient, KindServer, KindClientServer:
		return true
	}
	return false
}

// Limits on certificate lifetimes.
const (
	MaxCAValidity   = 30 * 365 * 24 * time.Hour
	MaxLeafValidity = 10 * 365 * 24 * time.Hour
	// backdate protects against small clock differences between hosts.
	backdate = 5 * time.Minute
)

// Subject holds the distinguished name fields a user can set.
type Subject struct {
	CommonName         string
	Organization       string
	OrganizationalUnit string
	Country            string
	Province           string
	Locality           string
}

func (s Subject) pkix() pkix.Name {
	n := pkix.Name{CommonName: s.CommonName}
	if s.Organization != "" {
		n.Organization = []string{s.Organization}
	}
	if s.OrganizationalUnit != "" {
		n.OrganizationalUnit = []string{s.OrganizationalUnit}
	}
	if s.Country != "" {
		n.Country = []string{s.Country}
	}
	if s.Province != "" {
		n.Province = []string{s.Province}
	}
	if s.Locality != "" {
		n.Locality = []string{s.Locality}
	}
	return n
}

// SANs are the subject alternative names.
type SANs struct {
	DNSNames []string
	IPs      []net.IP
	Emails   []string
	URIs     []*url.URL
}

// Empty reports whether no SAN is set.
func (s SANs) Empty() bool {
	return len(s.DNSNames)+len(s.IPs)+len(s.Emails)+len(s.URIs) == 0
}

// Request describes a certificate to issue.
type Request struct {
	Kind      Kind
	Subject   Subject
	SANs      SANs
	KeyType   KeyType          // used when PublicKey is nil
	PublicKey crypto.PublicKey // set when signing a CSR; no key is generated
	Validity  time.Duration
	// PathLen limits the depth of CAs below this one. -1 means unlimited.
	// Only used for CAs.
	PathLen int
	// CRLURL is embedded as the CRL distribution point. Empty for roots.
	CRLURL string
	Now    time.Time // zero means time.Now()
}

// Signer is a CA that can issue certificates.
type Signer struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

// Issued is the result of Issue.
type Issued struct {
	Cert *x509.Certificate
	DER  []byte
	Key  crypto.Signer // nil when a CSR was signed
}

var dnsLabel = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)

// ValidateDNSName checks a DNS SAN (wildcards only as the leftmost label).
func ValidateDNSName(n string) error {
	if len(n) == 0 || len(n) > 253 || !dnsLabel.MatchString(n) {
		return fmt.Errorf("invalid DNS name %q", n)
	}
	return nil
}

func (r *Request) validate(issuer *Signer) error {
	if !r.Kind.Valid() {
		return fmt.Errorf("pki: unknown kind %q", r.Kind)
	}
	cn := strings.TrimSpace(r.Subject.CommonName)
	if cn == "" || len(cn) > 64 {
		return errors.New("pki: common name is required (max 64 characters)")
	}
	if len(r.Subject.Country) != 0 && len(r.Subject.Country) != 2 {
		return errors.New("pki: country must be a 2-letter code")
	}
	if r.Validity <= 0 {
		return errors.New("pki: validity must be positive")
	}
	maxV := MaxLeafValidity
	if r.Kind.IsCA() {
		maxV = MaxCAValidity
	}
	if r.Validity > maxV {
		return fmt.Errorf("pki: validity exceeds maximum of %d days", int(maxV.Hours()/24))
	}
	if r.PublicKey == nil && !r.KeyType.Valid() {
		return fmt.Errorf("pki: unsupported key type %q", r.KeyType)
	}
	for _, d := range r.SANs.DNSNames {
		if err := ValidateDNSName(d); err != nil {
			return fmt.Errorf("pki: %w", err)
		}
	}
	for _, e := range r.SANs.Emails {
		if a, err := mail.ParseAddress(e); err != nil || a.Address != e {
			return fmt.Errorf("pki: invalid email %q", e)
		}
	}
	for _, u := range r.SANs.URIs {
		if u.Scheme == "" {
			return fmt.Errorf("pki: URI SAN %q needs a scheme", u.String())
		}
	}
	if r.Kind == KindServer || r.Kind == KindClientServer {
		if len(r.SANs.DNSNames)+len(r.SANs.IPs) == 0 {
			return errors.New("pki: server certificates need at least one DNS name or IP address")
		}
	}
	switch {
	case r.Kind == KindRoot && issuer != nil:
		return errors.New("pki: a root CA is self-signed and takes no issuer")
	case r.Kind != KindRoot && issuer == nil:
		return errors.New("pki: an issuer CA is required")
	}
	if issuer != nil {
		if !issuer.Cert.IsCA || issuer.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return errors.New("pki: issuer is not a CA")
		}
		if r.Kind == KindIntermediate && issuer.Cert.MaxPathLenZero {
			return errors.New("pki: issuer has path length 0 and can't sign intermediate CAs")
		}
	}
	return nil
}

// Issue creates and signs a certificate. Roots are self-signed.
func Issue(r Request, issuer *Signer) (*Issued, error) {
	if err := r.validate(issuer); err != nil {
		return nil, err
	}
	now := r.Now
	if now.IsZero() {
		now = time.Now()
	}
	notBefore := now.Add(-backdate).UTC().Truncate(time.Second)
	notAfter := now.Add(r.Validity).UTC().Truncate(time.Second)
	if issuer != nil {
		if now.After(issuer.Cert.NotAfter) || now.Before(issuer.Cert.NotBefore) {
			return nil, errors.New("pki: issuer CA is expired or not yet valid")
		}
		if notAfter.After(issuer.Cert.NotAfter) {
			return nil, fmt.Errorf("pki: certificate would outlive its issuer (issuer expires %s)", issuer.Cert.NotAfter.Format(time.DateOnly))
		}
	}

	var key crypto.Signer
	pub := r.PublicKey
	if pub == nil {
		var err error
		key, err = GenerateKey(r.KeyType)
		if err != nil {
			return nil, err
		}
		pub = key.Public()
	} else if _, err := KeyTypeOf(pub); err != nil {
		return nil, err
	}

	serial, err := NewSerial()
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(pub)
	if err != nil {
		return nil, err
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               r.Subject.pkix(),
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SubjectKeyId:          ski,
		BasicConstraintsValid: true,
		DNSNames:              r.SANs.DNSNames,
		IPAddresses:           r.SANs.IPs,
		EmailAddresses:        r.SANs.Emails,
		URIs:                  r.SANs.URIs,
	}
	if r.CRLURL != "" {
		tmpl.CRLDistributionPoints = []string{r.CRLURL}
	}

	switch r.Kind {
	case KindRoot, KindIntermediate:
		tmpl.IsCA = true
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
		switch {
		case r.PathLen < 0:
			tmpl.MaxPathLen = -1
		case r.PathLen == 0:
			tmpl.MaxPathLen = 0
			tmpl.MaxPathLenZero = true
		default:
			tmpl.MaxPathLen = r.PathLen
		}
		if issuer != nil && issuer.Cert.MaxPathLen > 0 && (tmpl.MaxPathLen < 0 || tmpl.MaxPathLen >= issuer.Cert.MaxPathLen) {
			// Keep the chain consistent: a child CA must allow fewer levels than its parent.
			tmpl.MaxPathLen = issuer.Cert.MaxPathLen - 1
			tmpl.MaxPathLenZero = tmpl.MaxPathLen == 0
		}
	default:
		tmpl.IsCA = false
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		if _, isRSA := pub.(*rsa.PublicKey); isRSA {
			// RSA key exchange in TLS 1.2 needs keyEncipherment.
			tmpl.KeyUsage |= x509.KeyUsageKeyEncipherment
		}
		switch r.Kind {
		case KindClient:
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		case KindServer:
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		case KindClientServer:
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		}
	}

	parent, signKey := tmpl, key
	if issuer != nil {
		parent, signKey = issuer.Cert, issuer.Key
		tmpl.AuthorityKeyId = issuer.Cert.SubjectKeyId
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signKey)
	if err != nil {
		return nil, fmt.Errorf("pki: sign certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse new certificate: %w", err)
	}
	return &Issued{Cert: cert, DER: der, Key: key}, nil
}

// NewSerial returns a random positive 128-bit serial number.
func NewSerial() (*big.Int, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("pki: serial: %w", err)
	}
	b[0] &= 0x7f // keep it positive and within 20 octets when DER-encoded
	b[0] |= 0x40 // and never shorter than 127 bits
	return new(big.Int).SetBytes(b), nil
}

// subjectKeyID uses RFC 7093 method 1: the leftmost 160 bits of the
// SHA-256 hash of the subjectPublicKey BIT STRING.
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal public key: %w", err)
	}
	var info struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		return nil, fmt.Errorf("pki: parse public key: %w", err)
	}
	sum := sha256.Sum256(info.PublicKey.Bytes)
	return sum[:20], nil
}

// KeyMatchesCert reports whether key is the private key for cert.
func KeyMatchesCert(key crypto.Signer, cert *x509.Certificate) bool {
	a, err1 := x509.MarshalPKIXPublicKey(key.Public())
	b, err2 := x509.MarshalPKIXPublicKey(cert.PublicKey)
	return err1 == nil && err2 == nil && bytes.Equal(a, b)
}

// KindOf guesses the kind of an existing certificate (used for imports).
func KindOf(c *x509.Certificate) Kind {
	if c.IsCA {
		if bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil {
			return KindRoot
		}
		return KindIntermediate
	}
	var client, server bool
	for _, u := range c.ExtKeyUsage {
		switch u {
		case x509.ExtKeyUsageClientAuth:
			client = true
		case x509.ExtKeyUsageServerAuth:
			server = true
		case x509.ExtKeyUsageAny:
			client, server = true, true
		}
	}
	switch {
	case client && server, len(c.ExtKeyUsage) == 0:
		return KindClientServer
	case server:
		return KindServer
	default:
		return KindClient
	}
}
