// Package crypto encrypts secret material (private keys, TOTP secrets) at rest
// with a master key, using AES-256-GCM.
//
// Ciphertext format: version(1) || nonce(12) || GCM(ciphertext+tag).
// Every Seal call uses a fresh random nonce. The caller passes associated
// data (AAD) that binds the ciphertext to its context, e.g. "cert-key:42",
// so a blob can't be moved to another DB row and still decrypt.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// KeySize is the master key length in bytes (AES-256).
	KeySize    = 32
	versionV1  = 1
	nonceSize  = 12
	minBlobLen = 1 + nonceSize + 16
)

// ErrDecrypt is returned for any failure to open a blob. It never says why,
// so it can't be used as an oracle.
var ErrDecrypt = errors.New("crypto: unable to decrypt")

// Envelope seals and opens blobs with the master key.
type Envelope struct {
	aead cipher.AEAD
}

// New builds an Envelope from a 32-byte master key.
func New(key []byte) (*Envelope, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto: master key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: init cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: init gcm: %w", err)
	}
	return &Envelope{aead: aead}, nil
}

// Seal encrypts plaintext and binds it to aad.
func (e *Envelope) Seal(plaintext []byte, aad string) ([]byte, error) {
	out := make([]byte, 1+nonceSize, 1+nonceSize+len(plaintext)+e.aead.Overhead())
	out[0] = versionV1
	if _, err := rand.Read(out[1 : 1+nonceSize]); err != nil {
		return nil, fmt.Errorf("crypto: nonce: %w", err)
	}
	return e.aead.Seal(out, out[1:1+nonceSize], plaintext, []byte(aad)), nil
}

// Open decrypts a blob produced by Seal with the same aad.
func (e *Envelope) Open(blob []byte, aad string) ([]byte, error) {
	if len(blob) < minBlobLen || blob[0] != versionV1 {
		return nil, ErrDecrypt
	}
	pt, err := e.aead.Open(nil, blob[1:1+nonceSize], blob[1+nonceSize:], []byte(aad))
	if err != nil {
		return nil, ErrDecrypt
	}
	return pt, nil
}

// LoadOrCreateKey reads the master key file (base64, one line). If the file
// doesn't exist, it generates a new key and writes it with 0600 permissions.
// Returns created=true when a new key was generated.
func LoadOrCreateKey(path string) (key []byte, created bool, err error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from admin config
	if err == nil {
		if err := checkKeyFilePerms(path); err != nil {
			return nil, false, err
		}
		key, err = decodeKey(data)
		return key, false, err
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("crypto: read master key: %w", err)
	}
	key = make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, false, fmt.Errorf("crypto: generate master key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, false, fmt.Errorf("crypto: create key dir: %w", err)
	}
	// O_EXCL: never overwrite an existing key, even in a race.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- admin config
	if err != nil {
		return nil, false, fmt.Errorf("crypto: create master key file: %w", err)
	}
	if _, err := f.WriteString(base64.StdEncoding.EncodeToString(key) + "\n"); err != nil {
		_ = f.Close()
		return nil, false, fmt.Errorf("crypto: write master key: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, false, fmt.Errorf("crypto: close master key: %w", err)
	}
	return key, true, nil
}

func decodeKey(data []byte) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(key) != KeySize {
		return nil, fmt.Errorf("crypto: master key file must contain %d bytes, base64-encoded", KeySize)
	}
	return key, nil
}

// checkKeyFilePerms refuses a master key that other users can read.
func checkKeyFilePerms(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("crypto: stat master key: %w", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("crypto: master key file %s is accessible by group/others (mode %o); run: chmod 600 %s", path, st.Mode().Perm(), path)
	}
	return nil
}
