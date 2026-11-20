// Package backup creates and restores Certly backups.
//
// A backup is a tar.gz with exactly two files: manifest.json and certly.db
// (a VACUUM INTO snapshot). With a passphrase, the whole archive is encrypted
// with age (scrypt), so it can also be opened with the standard `age -d` tool.
// The master key is never part of a backup.
package backup

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"

	"github.com/quantumryuu/Certly/internal/store"
)

// File names.
const (
	DBName       = "certly.db"
	manifestName = "manifest.json"
	lockName     = "certly.lock"
	ageMagic     = "age-encryption.org/v1"
	// Limits for restore input, so a hostile archive can't fill the disk.
	maxDBSize       = 4 << 30
	maxManifestSize = 64 << 10
	formatVersion   = 1
)

// Manifest describes a backup.
type Manifest struct {
	Format        int       `json:"format"`
	AppVersion    string    `json:"app_version"`
	SchemaVersion int       `json:"schema_version"`
	CreatedAt     time.Time `json:"created_at"`
	DBSHA256      string    `json:"db_sha256"`
	DBSize        int64     `json:"db_size"`
}

// Write snapshots the store and writes a backup archive to w.
// tmpDir must be on a filesystem with room for one DB copy.
func Write(ctx context.Context, st *store.Store, w io.Writer, passphrase, appVersion, tmpDir string) (*Manifest, error) {
	tmp, err := os.MkdirTemp(tmpDir, ".certly-backup-")
	if err != nil {
		return nil, fmt.Errorf("backup: temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)
	snap := filepath.Join(tmp, DBName)
	if err := st.Snapshot(ctx, snap); err != nil {
		return nil, err
	}
	schema, err := st.SchemaVersion(ctx)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(snap) // #nosec G304 -- our own temp file
	if err != nil {
		return nil, fmt.Errorf("backup: open snapshot: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return nil, fmt.Errorf("backup: hash snapshot: %w", err)
	}
	m := &Manifest{Format: formatVersion, AppVersion: appVersion, SchemaVersion: schema, CreatedAt: time.Now().UTC(),
		DBSHA256: hex.EncodeToString(h.Sum(nil)), DBSize: size}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}

	out := w
	var ageW io.WriteCloser
	if passphrase != "" {
		r, err := age.NewScryptRecipient(passphrase)
		if err != nil {
			return nil, fmt.Errorf("backup: passphrase: %w", err)
		}
		if ageW, err = age.Encrypt(w, r); err != nil {
			return nil, fmt.Errorf("backup: encrypt: %w", err)
		}
		out = ageW
	}
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	mj, _ := json.MarshalIndent(m, "", "  ")
	if err := writeEntry(tw, manifestName, int64(len(mj)), bytes.NewReader(mj)); err != nil {
		return nil, err
	}
	if err := writeEntry(tw, DBName, size, f); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("backup: close tar: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("backup: close gzip: %w", err)
	}
	if ageW != nil {
		if err := ageW.Close(); err != nil {
			return nil, fmt.Errorf("backup: close age: %w", err)
		}
	}
	return m, nil
}

func writeEntry(tw *tar.Writer, name string, size int64, r io.Reader) error {
	hdr := &tar.Header{Name: name, Mode: 0o600, Size: size, ModTime: time.Now(), Typeflag: tar.TypeReg}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("backup: tar header: %w", err)
	}
	if _, err := io.Copy(tw, r); err != nil {
		return fmt.Errorf("backup: tar write: %w", err)
	}
	return nil
}

// FileName returns the name for a backup made at t.
func FileName(t time.Time, encrypted bool) string {
	n := "certly-" + t.UTC().Format("20060102T150405Z") + ".tar.gz"
	if encrypted {
		n += ".age"
	}
	return n
}

// WriteFile writes a backup to path atomically with 0600 permissions.
func WriteFile(ctx context.Context, st *store.Store, path, passphrase, appVersion string) (*Manifest, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("backup: create dir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".certly-backup-*.part")
	if err != nil {
		return nil, fmt.Errorf("backup: create file: %w", err)
	}
	defer os.Remove(tmp.Name())
	bw := bufio.NewWriter(tmp)
	m, err := Write(ctx, st, bw, passphrase, appVersion, dir)
	if err == nil {
		err = bw.Flush()
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return nil, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return nil, fmt.Errorf("backup: rename: %w", err)
	}
	return m, nil
}

// Prune deletes the oldest backups in dir, keeping the newest keep files.
func Prune(dir string, keep int) ([]string, error) {
	if keep <= 0 {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("backup: read dir: %w", err)
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.Type().IsRegular() && strings.HasPrefix(n, "certly-") && (strings.HasSuffix(n, ".tar.gz") || strings.HasSuffix(n, ".tar.gz.age")) {
			names = append(names, n)
		}
	}
	sort.Strings(names) // timestamped names sort by time
	var removed []string
	for len(names) > keep {
		p := filepath.Join(dir, names[0])
		if err := os.Remove(p); err != nil {
			return removed, fmt.Errorf("backup: prune: %w", err)
		}
		removed = append(removed, p)
		names = names[1:]
	}
	return removed, nil
}

// ErrLocked means Certly is running against the data dir.
var ErrLocked = errors.New("another Certly process is using this data directory (is the service running? stop it first)")

// Lock takes an exclusive lock on the data dir. `serve` holds it while
// running, and restore takes it so the two can never overlap.
func Lock(dataDir string) (unlock func(), err error) {
	f, err := os.OpenFile(filepath.Join(dataDir, lockName), os.O_RDWR|os.O_CREATE, 0o600) // #nosec G304 -- admin config
	if err != nil {
		return nil, fmt.Errorf("backup: open lock: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil { // #nosec G115 -- fd fits in int
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("backup: lock: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) // #nosec G115
		_ = f.Close()
	}, nil
}

// IsEncrypted reports whether the backup file is age-encrypted.
func IsEncrypted(path string) (bool, error) {
	f, err := os.Open(path) // #nosec G304 -- admin-supplied path
	if err != nil {
		return false, fmt.Errorf("backup: open: %w", err)
	}
	defer f.Close()
	head := make([]byte, len(ageMagic))
	n, _ := io.ReadFull(f, head)
	return string(head[:n]) == ageMagic, nil
}

// Restore replaces the database in dataDir with the one in the backup at
// src. The current database is kept as certly.db.pre-restore.
func Restore(ctx context.Context, src, dataDir, passphrase string) (*Manifest, error) {
	unlock, err := Lock(dataDir)
	if err != nil {
		return nil, err
	}
	defer unlock()

	in, err := os.Open(src) // #nosec G304 -- admin-supplied path
	if err != nil {
		return nil, fmt.Errorf("backup: open: %w", err)
	}
	defer in.Close()
	br := bufio.NewReader(in)
	var r io.Reader = br
	if head, _ := br.Peek(len(ageMagic)); string(head) == ageMagic {
		if passphrase == "" {
			return nil, errors.New("backup: this backup is encrypted; a passphrase is required")
		}
		id, err := age.NewScryptIdentity(passphrase)
		if err != nil {
			return nil, fmt.Errorf("backup: passphrase: %w", err)
		}
		if r, err = age.Decrypt(br, id); err != nil {
			return nil, errors.New("backup: wrong passphrase or corrupt backup")
		}
	}
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("backup: not a Certly backup (gzip): %w", err)
	}
	defer gz.Close()

	tmp, err := os.MkdirTemp(dataDir, ".certly-restore-")
	if err != nil {
		return nil, fmt.Errorf("backup: temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)
	newDB := filepath.Join(tmp, DBName)

	var m *Manifest
	var dbHash string
	var dbSize int64
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("backup: read archive: %w", err)
		}
		// Only two exact, flat names are accepted: no paths, no links, no
		// devices. This rules out zip-slip style traversal.
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("backup: unexpected entry type for %q", hdr.Name)
		}
		switch hdr.Name {
		case manifestName:
			if m != nil || hdr.Size > maxManifestSize {
				return nil, errors.New("backup: invalid manifest entry")
			}
			var mm Manifest
			if err := json.NewDecoder(io.LimitReader(tr, maxManifestSize)).Decode(&mm); err != nil {
				return nil, fmt.Errorf("backup: parse manifest: %w", err)
			}
			m = &mm
		case DBName:
			if dbHash != "" || hdr.Size > maxDBSize {
				return nil, errors.New("backup: invalid database entry")
			}
			f, err := os.OpenFile(newDB, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- fixed name in our temp dir
			if err != nil {
				return nil, fmt.Errorf("backup: write db: %w", err)
			}
			h := sha256.New()
			n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(tr, maxDBSize+1))
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				return nil, fmt.Errorf("backup: write db: %w", err)
			}
			if n > maxDBSize {
				return nil, errors.New("backup: database too large")
			}
			dbHash, dbSize = hex.EncodeToString(h.Sum(nil)), n
		default:
			return nil, fmt.Errorf("backup: unexpected file %q in archive", hdr.Name)
		}
	}
	if m == nil || dbHash == "" {
		return nil, errors.New("backup: archive is missing the manifest or database")
	}
	if m.Format != formatVersion {
		return nil, fmt.Errorf("backup: unsupported backup format %d", m.Format)
	}
	if m.DBSHA256 != dbHash || m.DBSize != dbSize {
		return nil, errors.New("backup: database checksum mismatch; the backup is corrupt")
	}
	if m.SchemaVersion > store.LatestSchemaVersion() {
		return nil, fmt.Errorf("backup: made by a newer Certly (schema %d > %d); upgrade first", m.SchemaVersion, store.LatestSchemaVersion())
	}
	// Opening checks integrity and applies any newer migrations.
	st, err := store.Open(ctx, newDB)
	if err != nil {
		return nil, fmt.Errorf("backup: restored database is unusable: %w", err)
	}
	var check string
	if err := st.DB().QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&check); err != nil || check != "ok" {
		_ = st.Close()
		return nil, fmt.Errorf("backup: integrity check failed: %s %v", check, err)
	}
	if _, err := st.DB().ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		_ = st.Close()
		return nil, fmt.Errorf("backup: checkpoint: %w", err)
	}
	if err := st.Close(); err != nil {
		return nil, err
	}

	cur := filepath.Join(dataDir, DBName)
	if _, err := os.Stat(cur); err == nil {
		for _, sfx := range []string{"", "-wal", "-shm"} {
			if err := os.Rename(cur+sfx, cur+".pre-restore"+sfx); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("backup: keep current db: %w", err)
			}
		}
	}
	for _, sfx := range []string{"-wal", "-shm"} {
		_ = os.Remove(newDB + sfx)
	}
	if err := os.Rename(newDB, cur); err != nil {
		return nil, fmt.Errorf("backup: install restored db: %w", err)
	}
	return m, nil
}
