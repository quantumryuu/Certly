package store

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func openTest(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "certly.db")
	s, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, path
}

func TestMigrationsAndPerms(t *testing.T) {
	s, path := openTest(t)
	v, err := s.SchemaVersion(context.Background())
	if err != nil || v != LatestSchemaVersion() || v < 1 {
		t.Fatalf("version %d (latest %d): %v", v, LatestSchemaVersion(), err)
	}
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("db mode %o", st.Mode().Perm())
	}
	// Re-opening is a no-op.
	s.Close()
	s2, err := Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()
}

func TestRefusesNewerSchema(t *testing.T) {
	s, path := openTest(t)
	if _, err := s.DB().Exec(`INSERT INTO schema_migrations VALUES (999, '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(context.Background(), path); err == nil {
		t.Fatal("opened a DB from a newer version")
	}
}

func TestCreateFirstUserOnlyOnce(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.CreateFirstUser(ctx, "admin", "hash"); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if n, _ := s.CountUsers(ctx); ok != 1 || n != 1 {
		t.Fatalf("created %d users (%d succeeded)", n, ok)
	}
}

func TestSearchEscapesWildcards(t *testing.T) {
	s, _ := openTest(t)
	ctx := context.Background()
	err := s.Tx(ctx, func(tx *sql.Tx) error {
		for _, cn := range []string{"alpha", "beta_x", "gamma%"} {
			if _, err := s.InsertCertTx(ctx, tx, &Cert{Kind: "client", CommonName: cn, Subject: "CN=" + cn, Serial: cn, KeyType: "ecdsa-p256",
				NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), DER: []byte{1}}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for q, want := range map[string]int{"_": 1, "%": 1, "a": 3, "' OR 1=1 --": 0} {
		got, err := s.ListCerts(ctx, CertFilter{Search: q}, time.Now())
		if err != nil || len(got) != want {
			t.Fatalf("search %q: %d results, want %d (%v)", q, len(got), want, err)
		}
	}
}

func TestSnapshot(t *testing.T) {
	s, _ := openTest(t)
	dst := filepath.Join(t.TempDir(), "snap.db")
	if err := s.Snapshot(context.Background(), dst); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(context.Background(), dst)
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()
}
