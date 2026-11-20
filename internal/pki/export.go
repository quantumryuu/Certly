package pki

import (
	"archive/zip"
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/youmark/pkcs8"
	"software.sslmate.com/src/go-pkcs12"
)

// kdfIterations is used for PBKDF2-HMAC-SHA256 in encrypted keys and P12 files
// (OWASP 2023 recommendation for PBKDF2-SHA256).
const kdfIterations = 600_000

// MinExportPassword is the shortest password accepted for protected exports.
const MinExportPassword = 8

// Bundle is what an export works on.
type Bundle struct {
	Cert  *x509.Certificate
	Chain []*x509.Certificate // issuer first, root last; empty for a root
	Key   crypto.Signer       // nil if no key is stored (e.g. CSR-signed)
}

// ExportOptions controls an export.
type ExportOptions struct {
	Password   string // encrypts the key / P12; required for P12 and CA keys
	IncludeKey bool   // zip only: put the private key in the bundle
}

// File is one exported file.
type File struct {
	Name        string
	ContentType string
	Data        []byte
}

// Format is one export format.
type Format struct {
	ID          string
	Label       string
	NeedsKey    bool // only offered when a key is stored
	NeedsPass   bool // a password is mandatory
	Description string
	encode      func(b Bundle, opt ExportOptions, base string) (*File, error)
}

// Formats lists every export format, in UI order.
var Formats = []Format{
	{ID: "cert-pem", Label: "Certificate (PEM)", Description: "cert.pem", encode: encCertPEM},
	{ID: "cert-der", Label: "Certificate (DER)", Description: "cert.der: Java, Windows, appliances", encode: encCertDER},
	{ID: "chain-pem", Label: "CA chain (PEM)", Description: "issuer chain, without the certificate itself", encode: encChainPEM},
	{ID: "fullchain-pem", Label: "Full chain (PEM)", Description: "certificate + issuer chain: nginx, HAProxy, Traefik", encode: encFullchainPEM},
	{ID: "key-pem", Label: "Private key (PKCS#8 PEM)", NeedsKey: true, Description: "encrypted with AES-256 if a password is set", encode: encKeyPEM},
	{ID: "p12", Label: "PKCS#12 (.p12)", NeedsKey: true, NeedsPass: true, Description: "cert + key + chain: browsers, macOS/iOS/Android, Windows", encode: encP12},
	{ID: "zip", Label: "Zip bundle", Description: "cert, chain, fullchain, CA, and optionally key and .p12", encode: encZip},
}

// FormatByID finds a format.
func FormatByID(id string) (Format, bool) {
	for _, f := range Formats {
		if f.ID == id {
			return f, true
		}
	}
	return Format{}, false
}

// Export encodes the bundle in the given format.
func Export(b Bundle, formatID string, opt ExportOptions) (*File, error) {
	f, ok := FormatByID(formatID)
	if !ok {
		return nil, fmt.Errorf("pki: unknown export format %q", formatID)
	}
	if b.Cert == nil {
		return nil, errors.New("pki: nothing to export")
	}
	wantsKey := f.NeedsKey || (f.ID == "zip" && opt.IncludeKey)
	if wantsKey && b.Key == nil {
		return nil, errors.New("pki: no private key is stored for this certificate")
	}
	if opt.Password != "" && len(opt.Password) < MinExportPassword {
		return nil, fmt.Errorf("pki: password must be at least %d characters", MinExportPassword)
	}
	if f.NeedsPass && opt.Password == "" {
		return nil, errors.New("pki: this format requires a password")
	}
	if wantsKey && b.Cert.IsCA && opt.Password == "" {
		return nil, errors.New("pki: CA private keys can only be exported encrypted; set a password")
	}
	return f.encode(b, opt, FileBase(b.Cert.Subject.CommonName))
}

var (
	unsafeChars = regexp.MustCompile(`[^a-z0-9._-]+`)
	dotRuns     = regexp.MustCompile(`\.{2,}`)
)

// FileBase turns a common name into a safe file name stem.
func FileBase(cn string) string {
	s := unsafeChars.ReplaceAllString(strings.ToLower(cn), "-")
	s = dotRuns.ReplaceAllString(s, ".")
	s = strings.Trim(s, ".-")
	if len(s) > 64 {
		s = s[:64]
	}
	if s == "" {
		return "certificate"
	}
	return s
}

// CertPEM encodes certificates as PEM.
func CertPEM(certs ...*x509.Certificate) []byte {
	var buf bytes.Buffer
	for _, c := range certs {
		_ = pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
	}
	return buf.Bytes()
}

// KeyPEM encodes a private key as PKCS#8 PEM, encrypted when password is set
// (PBES2: PBKDF2-HMAC-SHA256 + AES-256-CBC, readable by OpenSSL).
func KeyPEM(key crypto.Signer, password string) ([]byte, error) {
	if password == "" {
		der, err := MarshalKey(key)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
	}
	der, err := pkcs8.MarshalPrivateKey(key, []byte(password), &pkcs8.Opts{
		Cipher:  pkcs8.AES256CBC,
		KDFOpts: pkcs8.PBKDF2Opts{SaltSize: 16, IterationCount: kdfIterations, HMACHash: crypto.SHA256},
	})
	if err != nil {
		return nil, fmt.Errorf("pki: encrypt key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: der}), nil
}

// P12 encodes cert, key and chain as PKCS#12 using AES-256 and SHA-256.
func P12(b Bundle, password string) ([]byte, error) {
	data, err := pkcs12.Modern.WithIterations(kdfIterations).Encode(b.Key, b.Cert, b.Chain, password)
	if err != nil {
		return nil, fmt.Errorf("pki: encode PKCS#12: %w", err)
	}
	return data, nil
}

const pemType = "application/x-pem-file"

func encCertPEM(b Bundle, _ ExportOptions, base string) (*File, error) {
	return &File{base + ".crt.pem", pemType, CertPEM(b.Cert)}, nil
}

func encCertDER(b Bundle, _ ExportOptions, base string) (*File, error) {
	return &File{base + ".der", "application/pkix-cert", b.Cert.Raw}, nil
}

func encChainPEM(b Bundle, _ ExportOptions, base string) (*File, error) {
	if len(b.Chain) == 0 {
		return nil, errors.New("pki: a root CA has no issuer chain; export the certificate instead")
	}
	return &File{base + ".chain.pem", pemType, CertPEM(b.Chain...)}, nil
}

func encFullchainPEM(b Bundle, _ ExportOptions, base string) (*File, error) {
	return &File{base + ".fullchain.pem", pemType, CertPEM(append([]*x509.Certificate{b.Cert}, b.Chain...)...)}, nil
}

func encKeyPEM(b Bundle, opt ExportOptions, base string) (*File, error) {
	data, err := KeyPEM(b.Key, opt.Password)
	if err != nil {
		return nil, err
	}
	return &File{base + ".key.pem", pemType, data}, nil
}

func encP12(b Bundle, opt ExportOptions, base string) (*File, error) {
	data, err := P12(b, opt.Password)
	if err != nil {
		return nil, err
	}
	return &File{base + ".p12", "application/x-pkcs12", data}, nil
}

type zipEntry struct {
	name, desc string
	data       []byte
}

func encZip(b Bundle, opt ExportOptions, base string) (*File, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	now := time.Now()
	add := func(name string, data []byte) error {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: base + "/" + name, Method: zip.Deflate, Modified: now})
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	}
	var readme strings.Builder
	fmt.Fprintf(&readme, "Certificate bundle for %q\nGenerated by Certly on %s\n\n", b.Cert.Subject.CommonName, now.UTC().Format(time.RFC3339))
	fmt.Fprintf(&readme, "Serial:     %X\nValid:      %s to %s\n\nFiles:\n", b.Cert.SerialNumber, b.Cert.NotBefore.Format(time.DateOnly), b.Cert.NotAfter.Format(time.DateOnly))

	files := []zipEntry{{"cert.pem", "the certificate", CertPEM(b.Cert)}}
	if len(b.Chain) > 0 {
		files = append(files,
			zipEntry{"chain.pem", "issuer chain (intermediate(s) + root)", CertPEM(b.Chain...)},
			zipEntry{"fullchain.pem", "certificate + issuer chain", CertPEM(append([]*x509.Certificate{b.Cert}, b.Chain...)...)},
			zipEntry{"ca.pem", "root CA only (trust anchor)", CertPEM(b.Chain[len(b.Chain)-1])},
		)
	}
	if opt.IncludeKey {
		key, err := KeyPEM(b.Key, opt.Password)
		if err != nil {
			return nil, err
		}
		desc := "private key (UNENCRYPTED, protect this file)"
		if opt.Password != "" {
			desc = "private key, encrypted with your password"
		}
		files = append(files, zipEntry{"key.pem", desc, key})
		if opt.Password != "" {
			p12, err := P12(b, opt.Password)
			if err != nil {
				return nil, err
			}
			files = append(files, zipEntry{"bundle.p12", "PKCS#12 with cert + key + chain, same password", p12})
		}
	}
	for _, f := range files {
		if err := add(f.name, f.data); err != nil {
			return nil, fmt.Errorf("pki: write zip: %w", err)
		}
		fmt.Fprintf(&readme, "  %-14s %s\n", f.name, f.desc)
	}
	if err := add("README.txt", []byte(readme.String())); err != nil {
		return nil, fmt.Errorf("pki: write zip: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("pki: close zip: %w", err)
	}
	return &File{base + ".zip", "application/zip", buf.Bytes()}, nil
}
