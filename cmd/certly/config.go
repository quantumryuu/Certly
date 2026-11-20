package main

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// config is every setting. Each one is an env var with a matching flag;
// flags win. Keep this table in sync with the README.
type config struct {
	Listen         string
	DataDir        string
	BaseURL        string
	MasterKeyFile  string
	TLSCert        string
	TLSKey         string
	LogFormat      string
	LogLevel       string
	TrustedProxies string
	CRLValidity    time.Duration
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func defaultDataDir() string {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "/data"
	}
	return "/var/lib/certly"
}

// bindConfig registers the shared flags on fs.
func bindConfig(fs *flag.FlagSet) *config {
	c := &config{}
	fs.StringVar(&c.DataDir, "data-dir", env("CERTLY_DATA_DIR", defaultDataDir()), "data directory (env CERTLY_DATA_DIR)")
	fs.StringVar(&c.MasterKeyFile, "master-key-file", env("CERTLY_MASTER_KEY_FILE", ""), "master key file (env CERTLY_MASTER_KEY_FILE, default <data-dir>/master.key)")
	fs.StringVar(&c.BaseURL, "base-url", env("CERTLY_BASE_URL", "http://localhost:8080"), "public URL, used in CRL distribution points (env CERTLY_BASE_URL)")
	fs.StringVar(&c.LogFormat, "log-format", env("CERTLY_LOG_FORMAT", "text"), "text or json (env CERTLY_LOG_FORMAT)")
	fs.StringVar(&c.LogLevel, "log-level", env("CERTLY_LOG_LEVEL", "info"), "debug, info, warn, error (env CERTLY_LOG_LEVEL)")
	crl := env("CERTLY_CRL_VALIDITY", "168h")
	d, err := time.ParseDuration(crl)
	if err != nil {
		d = 0 // rejected in validate
	}
	fs.DurationVar(&c.CRLValidity, "crl-validity", d, "how long each CRL is valid; refreshed at half-life (env CERTLY_CRL_VALIDITY)")
	return c
}

func bindServeConfig(fs *flag.FlagSet) *config {
	c := bindConfig(fs)
	fs.StringVar(&c.Listen, "listen", env("CERTLY_LISTEN", ":8080"), "listen address (env CERTLY_LISTEN)")
	fs.StringVar(&c.TLSCert, "tls-cert", env("CERTLY_TLS_CERT", ""), "serve HTTPS with this certificate (env CERTLY_TLS_CERT)")
	fs.StringVar(&c.TLSKey, "tls-key", env("CERTLY_TLS_KEY", ""), "private key for -tls-cert (env CERTLY_TLS_KEY)")
	fs.StringVar(&c.TrustedProxies, "trusted-proxies", env("CERTLY_TRUSTED_PROXIES", ""), "comma-separated CIDRs whose X-Forwarded-For is trusted (env CERTLY_TRUSTED_PROXIES)")
	return c
}

func (c *config) finish(serve bool) error {
	abs, err := filepath.Abs(c.DataDir)
	if err != nil {
		return fmt.Errorf("data dir: %w", err)
	}
	c.DataDir = abs
	if c.MasterKeyFile == "" {
		c.MasterKeyFile = filepath.Join(c.DataDir, "master.key")
	}
	u, err := url.Parse(c.BaseURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("CERTLY_BASE_URL must look like https://certly.lan (got %q)", c.BaseURL)
	}
	c.BaseURL = strings.TrimRight(c.BaseURL, "/")
	if c.LogFormat != "text" && c.LogFormat != "json" {
		return errors.New("CERTLY_LOG_FORMAT must be text or json")
	}
	if c.CRLValidity < time.Hour || c.CRLValidity > 90*24*time.Hour {
		return errors.New("CERTLY_CRL_VALIDITY must be between 1h and 2160h (90 days)")
	}
	if !serve {
		return nil
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("set both CERTLY_TLS_CERT and CERTLY_TLS_KEY, or neither")
	}
	_, err = c.proxies()
	return err
}

func (c *config) proxies() ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, p := range strings.Split(c.TrustedProxies, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if !strings.Contains(p, "/") {
			if a, err := netip.ParseAddr(p); err == nil {
				out = append(out, netip.PrefixFrom(a, a.BitLen()))
				continue
			}
		}
		pref, err := netip.ParsePrefix(p)
		if err != nil {
			return nil, fmt.Errorf("CERTLY_TRUSTED_PROXIES: invalid CIDR %q", p)
		}
		out = append(out, pref.Masked())
	}
	return out, nil
}

// secure reports whether users reach Certly over HTTPS.
func (c *config) secure() bool {
	return strings.HasPrefix(c.BaseURL, "https://") || c.TLSCert != ""
}

func (c *config) logger() *slog.Logger {
	var lvl slog.Level
	_ = lvl.UnmarshalText([]byte(c.LogLevel))
	opts := &slog.HandlerOptions{Level: lvl}
	if c.LogFormat == "json" {
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, opts))
}
