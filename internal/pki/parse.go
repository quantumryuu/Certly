package pki

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/youmark/pkcs8"
)

// MaxPEMInput caps the size of uploaded PEM data (certs, keys, CSRs).
const MaxPEMInput = 64 << 10

// ParseCertificates reads one or more certificates from PEM or a single DER cert.
func ParseCertificates(data []byte) ([]*x509.Certificate, error) {
	if len(data) > MaxPEMInput {
		return nil, errors.New("pki: input too large")
	}
	var out []*x509.Certificate
	rest := data
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("pki: parse certificate: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		c, err := x509.ParseCertificate(data)
		if err != nil {
			return nil, errors.New("pki: no certificate found (expected PEM or DER)")
		}
		out = append(out, c)
	}
	return out, nil
}

// ParsePrivateKey reads a PEM private key: PKCS#8 (plain or encrypted),
// PKCS#1 RSA, or SEC1 EC. Legacy "Proc-Type: 4,ENCRYPTED" PEM is rejected
// because it uses weak MD5-based key derivation.
func ParsePrivateKey(data []byte, password []byte) (crypto.Signer, error) {
	if len(data) > MaxPEMInput {
		return nil, errors.New("pki: input too large")
	}
	rest := data
	for {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return nil, errors.New("pki: no private key found in PEM")
		}
		if _, legacy := b.Headers["DEK-Info"]; legacy {
			return nil, errors.New("pki: legacy encrypted PEM keys are not supported; convert with: openssl pkcs8 -topk8 -v2 aes-256-cbc")
		}
		var key any
		var err error
		switch b.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(b.Bytes)
		case "ENCRYPTED PRIVATE KEY":
			if len(password) == 0 {
				return nil, errors.New("pki: key is encrypted; a password is required")
			}
			key, _, err = pkcs8.ParsePrivateKey(b.Bytes, password)
			if err != nil {
				return nil, errors.New("pki: wrong password or corrupt encrypted key")
			}
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(b.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(b.Bytes)
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("pki: parse private key: %w", err)
		}
		s, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("pki: unsupported key type %T", key)
		}
		if _, err := KeyTypeOf(s.Public()); err != nil {
			return nil, err
		}
		return s, nil
	}
}

// ParseCSR reads a PEM or DER certificate signing request and checks its
// signature. Only the public key is used when signing: subject and SANs come
// from the form, so a CSR can't sneak in extensions.
func ParseCSR(data []byte) (*x509.CertificateRequest, error) {
	if len(data) > MaxPEMInput {
		return nil, errors.New("pki: input too large")
	}
	der := data
	if b, _ := pem.Decode(data); b != nil {
		if b.Type != "CERTIFICATE REQUEST" && b.Type != "NEW CERTIFICATE REQUEST" {
			return nil, fmt.Errorf("pki: expected a CERTIFICATE REQUEST, got %s", b.Type)
		}
		der = b.Bytes
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("pki: CSR signature is invalid: %w", err)
	}
	if _, err := KeyTypeOf(csr.PublicKey); err != nil {
		return nil, err
	}
	return csr, nil
}
