// Package pki holds the certificate authority logic: key generation, issuing,
// CRLs, parsing and export encoders. It has no HTTP or database code.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"fmt"
)

// KeyType names a supported key algorithm.
type KeyType string

// Supported key types. ECDSA P-256 is the default.
const (
	KeyECDSAP256 KeyType = "ecdsa-p256"
	KeyECDSAP384 KeyType = "ecdsa-p384"
	KeyRSA2048   KeyType = "rsa-2048"
	KeyRSA3072   KeyType = "rsa-3072"
	KeyRSA4096   KeyType = "rsa-4096"
	KeyEd25519   KeyType = "ed25519"
)

// KeyTypes lists the key types in the order the UI shows them.
var KeyTypes = []KeyType{KeyECDSAP256, KeyECDSAP384, KeyRSA2048, KeyRSA3072, KeyRSA4096, KeyEd25519}

// Valid reports whether k is supported.
func (k KeyType) Valid() bool {
	for _, t := range KeyTypes {
		if t == k {
			return true
		}
	}
	return false
}

// GenerateKey creates a new private key.
func GenerateKey(k KeyType) (crypto.Signer, error) {
	switch k {
	case KeyECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case KeyRSA3072:
		return rsa.GenerateKey(rand.Reader, 3072)
	case KeyRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	case KeyEd25519:
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		return priv, err
	default:
		return nil, fmt.Errorf("pki: unsupported key type %q", k)
	}
}

// KeyTypeOf describes a public key, and rejects weak or unsupported ones.
func KeyTypeOf(pub crypto.PublicKey) (KeyType, error) {
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		switch p.Curve {
		case elliptic.P256():
			return KeyECDSAP256, nil
		case elliptic.P384():
			return KeyECDSAP384, nil
		}
		return "", fmt.Errorf("pki: unsupported ECDSA curve %s", p.Curve.Params().Name)
	case *rsa.PublicKey:
		switch bits := p.N.BitLen(); {
		case bits < 2048:
			return "", fmt.Errorf("pki: RSA key too small (%d bits, minimum 2048)", bits)
		case bits <= 2048:
			return KeyRSA2048, nil
		case bits <= 3072:
			return KeyRSA3072, nil
		case bits <= 4096:
			return KeyRSA4096, nil
		default:
			return "", fmt.Errorf("pki: RSA key too large (%d bits, maximum 4096)", bits)
		}
	case ed25519.PublicKey:
		return KeyEd25519, nil
	default:
		return "", fmt.Errorf("pki: unsupported public key type %T", pub)
	}
}

// MarshalKey encodes a private key as unencrypted PKCS#8 DER. Only for
// passing to the at-rest envelope or an export encoder; never store the result.
func MarshalKey(k crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, fmt.Errorf("pki: marshal key: %w", err)
	}
	return der, nil
}

// UnmarshalKey decodes a PKCS#8 DER private key.
func UnmarshalKey(der []byte) (crypto.Signer, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse key: %w", err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("pki: key type %T can't sign", k)
	}
	return s, nil
}
