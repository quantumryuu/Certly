package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quantumryuu/Certly/internal/store"
)

func seed(t *testing.T, dir string) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(dir, DBName))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateFirstUser(context.Background(), "admin", "hash"); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestRoundTrip(t *testing.T) {
	for _, pass := range []string{"", "backup passphrase"} {
		t.Run("pass="+pass, func(t *testing.T) {
			ctx := context.Background()
			src := t.TempDir()
			st := seed(t, src)
			out := filepath.Join(t.TempDir(), FileName(time.Now(), pass != ""))
			if _, err := WriteFile(ctx, st, out, pass, "test"); err != nil {
				t.Fatal(err)
			}
			st.Close()
			fi, _ := os.Stat(out)
			if fi.Mode().Perm() != 0o600 {
				t.Fatalf("backup mode %o", fi.Mode().Perm())
			}
			raw, _ := os.ReadFile(out)
			if pass != "" && (bytes.Contains(raw, []byte("SQLite format")) || !bytes.HasPrefix(raw, []byte(ageMagic))) {
				t.Fatal("encrypted backup is not encrypted")
			}

			dst := t.TempDir()
			// Existing DB is kept aside.
			old := seed(t, dst)
			old.Close()
			if pass != "" {
				if _, err := Restore(ctx, out, dst, ""); err == nil {
					t.Fatal("restored encrypted backup without passphrase")
				}
				if _, err := Restore(ctx, out, dst, "wrong passphrase"); err == nil {
					t.Fatal("restored with wrong passphrase")
				}
			}
			m, err := Restore(ctx, out, dst, pass)
			if err != nil {
				t.Fatal(err)
			}
			if m.AppVersion != "test" {
				t.Fatalf("manifest %+v", m)
			}
			if _, err := os.Stat(filepath.Join(dst, DBName+".pre-restore")); err != nil {
				t.Fatal("previous DB not kept")
			}
			st2, err := store.Open(ctx, filepath.Join(dst, DBName))
			if err != nil {
				t.Fatal(err)
			}
			defer st2.Close()
			if n, _ := st2.CountUsers(ctx); n != 1 {
				t.Fatalf("restored %d users", n)
			}
		})
	}
}

func tarGz(t *testing.T, entries map[string]string, typ byte) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range entries {
		hdr := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(body)), Typeflag: typ}
		if typ == tar.TypeSymlink {
			hdr.Linkname, hdr.Size = "/etc/passwd", 0
		}
		_ = tw.WriteHeader(hdr)
		if typ == tar.TypeReg {
			_, _ = tw.Write([]byte(body))
		}
	}
	tw.Close()
	gz.Close()
	p := filepath.Join(t.TempDir(), "evil.tar.gz")
	_ = os.WriteFile(p, buf.Bytes(), 0o600)
	return p
}

func TestRestoreRejectsHostileArchives(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		entries map[string]string
		typ     byte
		want    string
	}{
		{"zip slip", map[string]string{"../../etc/cron.d/x": "boom"}, tar.TypeReg, "unexpected file"},
		{"absolute path", map[string]string{"/tmp/certly.db": "boom"}, tar.TypeReg, "unexpected file"},
		{"nested name", map[string]string{"sub/certly.db": "boom"}, tar.TypeReg, "unexpected file"},
		{"symlink", map[string]string{DBName: ""}, tar.TypeSymlink, "unexpected entry type"},
		{"missing manifest", map[string]string{DBName: "x"}, tar.TypeReg, "missing"},
		{"bad checksum", map[string]string{DBName: "x", manifestName: `{"format":1,"db_sha256":"00","db_size":1}`}, tar.TypeReg, "checksum"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dst := t.TempDir()
			_, err := Restore(ctx, tarGz(t, tc.entries, tc.typ), dst, "")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			entries, _ := os.ReadDir(dst)
			for _, e := range entries {
				if e.Name() != lockName {
					t.Fatalf("restore left %s behind", e.Name())
				}
			}
		})
	}
}

func TestLockBlocksRestore(t *testing.T) {
	dir := t.TempDir()
	unlock, err := Lock(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if _, err := Restore(context.Background(), "nonexistent", dir, ""); err != ErrLocked {
		t.Fatalf("got %v, want ErrLocked", err)
	}
}

func TestPrune(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		_ = os.WriteFile(filepath.Join(dir, FileName(base.Add(time.Duration(i)*time.Hour), i%2 == 0)), nil, 0o600)
	}
	_ = os.WriteFile(filepath.Join(dir, "unrelated.txt"), nil, 0o600)
	removed, err := Prune(dir, 2)
	if err != nil || len(removed) != 3 {
		t.Fatalf("removed %v, %v", removed, err)
	}
	left, _ := os.ReadDir(dir)
	if len(left) != 3 {
		t.Fatalf("%d files left", len(left))
	}
}
