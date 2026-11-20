// Command certly runs the Certly web app and its admin tools.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/quantumryuu/Certly/internal/auth"
	"github.com/quantumryuu/Certly/internal/backup"
	"github.com/quantumryuu/Certly/internal/ca"
	certcrypto "github.com/quantumryuu/Certly/internal/crypto"
	"github.com/quantumryuu/Certly/internal/jobs"
	"github.com/quantumryuu/Certly/internal/store"
	"github.com/quantumryuu/Certly/internal/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `Certly: a small private CA for homelab mTLS.

Usage:
  certly serve                         run the web app
  certly admin create   [-username U]  create the admin account (first run, headless)
  certly admin reset-password -username U
  certly admin disable-totp   -username U
  certly backup  -o FILE | -dir DIR [-keep N] [-encrypt]
  certly restore FILE                  (stop the service first)
  certly import  -cert FILE [-key FILE] [-key-password-stdin] [-notes TEXT]
  certly healthcheck                   exit 0 if the local server is healthy
  certly version

Run "certly <command> -h" for flags. Every flag also has a CERTLY_* env var.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "admin":
		err = cmdAdmin(args)
	case "backup":
		err = cmdBackup(args)
	case "restore":
		err = cmdRestore(args)
	case "import":
		err = cmdImport(args)
	case "healthcheck":
		err = cmdHealthcheck(args)
	case "version", "-v", "--version":
		fmt.Println("certly", version)
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "certly:", err)
		os.Exit(1)
	}
}

// prepareDataDir creates the data dir with 0700 and warns if it's too open.
func prepareDataDir(dir string, log *slog.Logger) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	st, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0o077 != 0 && log != nil {
		log.Warn("data directory is accessible by group/others; run chmod 700", "dir", dir, "mode", fmt.Sprintf("%o", st.Mode().Perm()))
	}
	return nil
}

// open loads the master key and database.
func open(ctx context.Context, c *config, log *slog.Logger, createKey bool) (*ca.Service, error) {
	if err := prepareDataDir(c.DataDir, log); err != nil {
		return nil, err
	}
	if !createKey {
		if _, err := os.Stat(c.MasterKeyFile); err != nil {
			return nil, fmt.Errorf("master key %s not found; run `certly serve` once, or point CERTLY_MASTER_KEY_FILE at your key", c.MasterKeyFile)
		}
	}
	key, created, err := certcrypto.LoadOrCreateKey(c.MasterKeyFile)
	if err != nil {
		return nil, err
	}
	if created {
		log.Warn("generated a new master key; BACK IT UP NOW, separately from your backups. Without it the CA keys can't be decrypted", "file", c.MasterKeyFile)
	}
	env, err := certcrypto.New(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(ctx, filepath.Join(c.DataDir, backup.DBName))
	if err != nil {
		return nil, err
	}
	if err := checkMasterKey(ctx, st, env); err != nil {
		_ = st.Close()
		return nil, err
	}
	return &ca.Service{Store: st, Env: env, BaseURL: c.BaseURL, CRLValidity: c.CRLValidity, Log: log}, nil
}

// checkMasterKey fails fast if the key can't open the stored CA keys
// (e.g. after restoring a backup with the wrong master key).
func checkMasterKey(ctx context.Context, st *store.Store, env *certcrypto.Envelope) error {
	ids, err := st.CAIDs(ctx)
	if err != nil || len(ids) == 0 {
		return err
	}
	c, err := st.CertByID(ctx, ids[0])
	if err != nil {
		return err
	}
	if _, err := env.Open(c.KeyEnc, fmt.Sprintf("cert-key:%d", c.ID)); err != nil {
		return errors.New("the master key does not match this database (CA keys can't be decrypted); check CERTLY_MASTER_KEY_FILE")
	}
	return nil
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	c := bindServeConfig(fs)
	_ = fs.Parse(args)
	if err := c.finish(true); err != nil {
		return err
	}
	log := c.logger()
	// Create the dir quietly; open() below checks its permissions and warns.
	if err := os.MkdirAll(c.DataDir, 0o700); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	unlock, err := backup.Lock(c.DataDir)
	if err != nil {
		return err
	}
	defer unlock()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	svc, err := open(ctx, c, log, true)
	if err != nil {
		return err
	}
	defer svc.Store.Close()
	proxies, _ := c.proxies()
	srv, err := web.New(web.Config{BaseURL: c.BaseURL, DataDir: c.DataDir, TrustedProxies: proxies, SecureCookies: c.secure(), Version: version}, svc, log)
	if err != nil {
		return err
	}
	go jobs.Run(ctx, svc, log)

	hs := &http.Server{
		Addr:              c.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      5 * time.Minute, // backup downloads
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}
	ln, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	if n, _ := svc.Store.CountUsers(ctx); n == 0 {
		log.Warn("no admin account yet: open /setup in the web UI, or run `certly admin create`")
	}
	if !c.secure() {
		log.Warn("cookies are not marked Secure: use HTTPS (CERTLY_TLS_CERT/CERTLY_TLS_KEY, or a TLS reverse proxy with CERTLY_SECURE_COOKIES=true)")
	}
	if c.BaseURL == "" {
		log.Info("CERTLY_BASE_URL not set: issued certificates won't contain a CRL address (fine when servers load the CRL from a file)")
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("certly listening", "addr", ln.Addr().String(), "base_url", c.BaseURL, "tls", c.TLSCert != "", "version", version)
		if c.TLSCert != "" {
			errc <- hs.ServeTLS(ln, c.TLSCert, c.TLSKey)
		} else {
			errc <- hs.Serve(ln)
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return hs.Shutdown(sctx)
}

// readSecret reads a secret from the terminal (no echo), or from stdin when
// it isn't a terminal (for scripts).
func readSecret(prompt string, confirm bool) (string, error) {
	fd := int(os.Stdin.Fd()) // #nosec G115 -- fd fits in int
	if !term.IsTerminal(fd) {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		return strings.TrimRight(line, "\r\n"), nil
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if confirm {
		fmt.Fprint(os.Stderr, "Repeat: ")
		b2, err := term.ReadPassword(fd)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", err
		}
		if string(b) != string(b2) {
			return "", errors.New("the two entries don't match")
		}
	}
	return string(b), nil
}

var cliActor = ca.Actor{Name: "cli"}

func cmdAdmin(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: certly admin create|reset-password|disable-totp -username U")
	}
	sub := args[0]
	fs := flag.NewFlagSet("admin "+sub, flag.ExitOnError)
	c := bindConfig(fs)
	username := fs.String("username", "admin", "username")
	_ = fs.Parse(args[1:])
	if err := c.finish(false); err != nil {
		return err
	}
	log := c.logger()
	ctx := context.Background()
	svc, err := open(ctx, c, log, sub == "create")
	if err != nil {
		return err
	}
	defer svc.Store.Close()
	st := svc.Store

	switch sub {
	case "create", "reset-password":
		pw, err := readSecret("New password: ", true)
		if err != nil {
			return err
		}
		if err := auth.ValidatePassword(pw); err != nil {
			return err
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return err
		}
		if sub == "create" {
			if _, err := st.CreateFirstUser(ctx, *username, hash); err != nil {
				return errors.New("an admin account already exists; use `certly admin reset-password`")
			}
			svc.Audit(ctx, cliActor, "setup", 0, "admin account created via CLI")
			fmt.Fprintf(os.Stderr, "Admin %q created.\n", *username)
			return nil
		}
		u, err := st.UserByName(ctx, *username)
		if err != nil {
			return fmt.Errorf("user %q not found", *username)
		}
		if err := st.SetPassword(ctx, u.ID, hash); err != nil {
			return err
		}
		svc.Audit(ctx, cliActor, "password-reset", 0, "via CLI; all sessions signed out")
		fmt.Fprintln(os.Stderr, "Password changed. Existing sessions are signed out.")
	case "disable-totp":
		u, err := st.UserByName(ctx, *username)
		if err != nil {
			return fmt.Errorf("user %q not found", *username)
		}
		if err := st.SetTOTP(ctx, u.ID, nil); err != nil {
			return err
		}
		svc.Audit(ctx, cliActor, "totp-disable", 0, "via CLI")
		fmt.Fprintln(os.Stderr, "Two-factor authentication disabled.")
	default:
		return fmt.Errorf("unknown admin command %q", sub)
	}
	return nil
}

func backupPassphrase(confirm bool) (string, error) {
	if p := os.Getenv("CERTLY_BACKUP_PASSPHRASE"); p != "" {
		return p, nil
	}
	return readSecret("Backup passphrase: ", confirm)
}

func cmdBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	c := bindConfig(fs)
	out := fs.String("o", "", "write the backup to this file")
	dir := fs.String("dir", "", "write a timestamped backup into this directory")
	keep := fs.Int("keep", 0, "with -dir: keep only the newest N backups (0 = keep all)")
	encrypt := fs.Bool("encrypt", false, "encrypt with a passphrase (env CERTLY_BACKUP_PASSPHRASE, or prompt)")
	_ = fs.Parse(args)
	if err := c.finish(false); err != nil {
		return err
	}
	if (*out == "") == (*dir == "") {
		return errors.New("use exactly one of -o FILE or -dir DIR")
	}
	pass := ""
	if *encrypt {
		var err error
		if pass, err = backupPassphrase(true); err != nil {
			return err
		}
		if len(pass) < auth.MinPasswordLength {
			return fmt.Errorf("backup passphrase must be at least %d characters", auth.MinPasswordLength)
		}
	}
	log := c.logger()
	ctx := context.Background()
	svc, err := open(ctx, c, log, false)
	if err != nil {
		return err
	}
	defer svc.Store.Close()
	path := *out
	if *dir != "" {
		path = filepath.Join(*dir, backup.FileName(time.Now(), *encrypt))
	}
	m, err := backup.WriteFile(ctx, svc.Store, path, pass, version)
	if err != nil {
		return err
	}
	svc.Audit(ctx, cliActor, "backup", 0, fmt.Sprintf("file=%s encrypted=%t size=%d", filepath.Base(path), *encrypt, m.DBSize))
	fmt.Fprintf(os.Stderr, "Backup written to %s (%d bytes of data, schema v%d).\n", path, m.DBSize, m.SchemaVersion)
	if *dir != "" && *keep > 0 {
		removed, err := backup.Prune(*dir, *keep)
		if err != nil {
			return err
		}
		for _, r := range removed {
			fmt.Fprintln(os.Stderr, "Removed old backup", r)
		}
	}
	fmt.Fprintln(os.Stderr, "Reminder: the master key is NOT in the backup. Keep it safe separately.")
	return nil
}

func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	c := bindConfig(fs)
	_ = fs.Parse(args)
	if err := c.finish(false); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: certly restore FILE")
	}
	src := fs.Arg(0)
	if err := prepareDataDir(c.DataDir, nil); err != nil {
		return err
	}
	pass := ""
	enc, err := backup.IsEncrypted(src)
	if err != nil {
		return err
	}
	if enc {
		if pass, err = backupPassphrase(false); err != nil {
			return err
		}
	}
	m, err := backup.Restore(context.Background(), src, c.DataDir, pass)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Restored backup from %s (Certly %s, schema v%d).\n", m.CreatedAt.Format(time.RFC3339), m.AppVersion, m.SchemaVersion)
	fmt.Fprintln(os.Stderr, "The previous database was kept as certly.db.pre-restore. Make sure CERTLY_MASTER_KEY_FILE is the key that belongs to this backup, then start Certly.")
	return nil
}

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	c := bindConfig(fs)
	certFile := fs.String("cert", "", "certificate file (PEM or DER)")
	keyFile := fs.String("key", "", "private key file (PEM), optional")
	keyPassStdin := fs.Bool("key-password-stdin", false, "read the key's password from stdin / prompt")
	notes := fs.String("notes", "", "notes to store with the certificate")
	_ = fs.Parse(args)
	if err := c.finish(false); err != nil {
		return err
	}
	if *certFile == "" {
		return errors.New("-cert is required")
	}
	certPEM, err := os.ReadFile(*certFile)
	if err != nil {
		return err
	}
	var keyPEM, keyPass []byte
	if *keyFile != "" {
		if keyPEM, err = os.ReadFile(*keyFile); err != nil {
			return err
		}
		defer clear(keyPEM)
	}
	if *keyPassStdin {
		p, err := readSecret("Key password: ", false)
		if err != nil {
			return err
		}
		keyPass = []byte(p)
	}
	log := c.logger()
	ctx := context.Background()
	svc, err := open(ctx, c, log, false)
	if err != nil {
		return err
	}
	defer svc.Store.Close()
	cert, err := svc.Import(ctx, cliActor, certPEM, keyPEM, keyPass, *notes)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Imported %s %q as #%d (key stored: %t).\n", cert.Kind, cert.CommonName, cert.ID, cert.HasKey())
	return nil
}

func cmdHealthcheck(args []string) error {
	fs := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	listen := fs.String("listen", env("CERTLY_LISTEN", ":8080"), "address the server listens on")
	tlsOn := fs.Bool("tls", env("CERTLY_TLS_CERT", "") != "", "server uses TLS")
	_ = fs.Parse(args)
	host, port, err := net.SplitHostPort(*listen)
	if err != nil {
		return err
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	scheme := "http"
	tr := &http.Transport{}
	if *tlsOn {
		scheme = "https"
		// Local liveness probe only; the cert is for the public name.
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} // #nosec G402
	}
	cl := &http.Client{Timeout: 5 * time.Second, Transport: tr}
	resp, err := cl.Get(scheme + "://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unhealthy: HTTP %d", resp.StatusCode)
	}
	return nil
}
