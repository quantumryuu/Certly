package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func testEnvelope(t *testing.T) *Envelope {
	t.Helper()
	e, err := New(bytes.Repeat([]byte{7}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestSealOpen(t *testing.T) {
	e := testEnvelope(t)
	pt := []byte("secret key material")
	blob, err := e.Seal(pt, "cert-key:1")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, pt) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := e.Open(blob, "cert-key:1")
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("round trip failed: %v", err)
	}
	blob2, _ := e.Seal(pt, "cert-key:1")
	if bytes.Equal(blob, blob2) {
		t.Fatal("two seals produced identical output (nonce reuse)")
	}
}

func TestOpenRejects(t *testing.T) {
	e := testEnvelope(t)
	blob, _ := e.Seal([]byte("x"), "a")
	tampered := append([]byte{}, blob...)
	tampered[len(tampered)-1] ^= 1
	other, _ := New(bytes.Repeat([]byte{8}, KeySize))

	tests := []struct {
		name string
		env  *Envelope
		blob []byte
		aad  string
	}{
		{"wrong aad", e, blob, "b"},
		{"tampered", e, tampered, "a"},
		{"wrong key", other, blob, "a"},
		{"short", e, blob[:5], "a"},
		{"bad version", e, append([]byte{9}, blob[1:]...), "a"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := tc.env.Open(tc.blob, tc.aad); err != ErrDecrypt {
				t.Fatalf("want ErrDecrypt, got %v", err)
			}
		})
	}
}

func TestNewKeySize(t *testing.T) {
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("accepted 16-byte key")
	}
}

func TestLoadOrCreateKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", "master.key")
	k1, created, err := LoadOrCreateKey(path)
	if err != nil || !created || len(k1) != KeySize {
		t.Fatalf("create: %v created=%v", err, created)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", st.Mode().Perm())
	}
	k2, created, err := LoadOrCreateKey(path)
	if err != nil || created || !bytes.Equal(k1, k2) {
		t.Fatalf("reload: %v created=%v", err, created)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadOrCreateKey(path); err == nil {
		t.Fatal("accepted world-readable key file")
	}
}
