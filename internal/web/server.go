// Package web is the HTTP UI: handlers, middleware and templates.
package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime/debug"
	"strings"
	"time"

	"github.com/alexedwards/scs/sqlite3store"
	"github.com/alexedwards/scs/v2"
	"github.com/go-chi/chi/v5"

	"github.com/quantumryuu/Certly/internal/auth"
	"github.com/quantumryuu/Certly/internal/ca"
	certcrypto "github.com/quantumryuu/Certly/internal/crypto"
	"github.com/quantumryuu/Certly/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

// maxBody caps every request body (forms, CSR and PEM uploads).
const maxBody = 1 << 20

// Config holds web settings.
type Config struct {
	BaseURL        string
	DataDir        string
	TrustedProxies []netip.Prefix
	AllowedOrigins []string // extra browser origins to trust, e.g. http://192.168.1.10:8080
	SecureCookies  bool
	Version        string
}

// Server is the web app.
type Server struct {
	cfg      Config
	svc      *ca.Service
	st       *store.Store
	env      *certcrypto.Envelope
	sessions *scs.SessionManager
	limiter  *auth.Limiter
	totp     *auth.TOTPVerifier
	pages    map[string]*pageTemplate
	log      *slog.Logger
	origins  []string
}

// NormalizeOrigin turns a URL like "https://certly.lan/" into the origin
// "https://certly.lan", rejecting anything that isn't a bare http(s) origin.
func NormalizeOrigin(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("web: %q is not an origin like https://certly.lan or http://192.168.1.10:8080", raw)
	}
	return u.Scheme + "://" + u.Host, nil
}

// New builds the server.
func New(cfg Config, svc *ca.Service, log *slog.Logger) (*Server, error) {
	var origins []string
	for _, o := range append([]string{cfg.BaseURL}, cfg.AllowedOrigins...) {
		if o == "" {
			continue
		}
		norm, err := NormalizeOrigin(o)
		if err != nil {
			return nil, err
		}
		origins = append(origins, norm)
	}
	sm := scs.New()
	sm.Store = sqlite3store.New(svc.Store.DB())
	sm.Lifetime = 12 * time.Hour
	sm.IdleTimeout = 2 * time.Hour
	sm.Cookie.HttpOnly = true
	sm.Cookie.SameSite = http.SameSiteStrictMode
	sm.Cookie.Path = "/"
	sm.Cookie.Secure = cfg.SecureCookies
	sm.Cookie.Persist = false
	if cfg.SecureCookies {
		sm.Cookie.Name = "__Host-certly"
	} else {
		sm.Cookie.Name = "certly_session"
	}
	pages, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg: cfg, svc: svc, st: svc.Store, env: svc.Env, sessions: sm,
		limiter: auth.NewLimiter(), totp: auth.NewTOTPVerifier(), pages: pages, log: log,
		origins: origins,
	}
	sm.ErrorFunc = func(w http.ResponseWriter, r *http.Request, err error) {
		s.log.Error("session error", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
	return s, nil
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(s.recoverer, s.clientIP, s.forwardedHost, s.securityHeaders, s.limitBody, s.logRequests)

	static, _ := fs.Sub(staticFS, "static")
	r.Handle("/static/*", http.StripPrefix("/static/", staticCache(http.FileServerFS(static))))
	// Public: health check and CRLs only.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	r.Get("/crl/{file}", s.handleCRL)

	// Same-origin requests (Origin matches Host) are always allowed. The base
	// URL and CERTLY_ALLOWED_ORIGINS are trusted too, for proxies that rewrite Host.
	cop := http.NewCrossOriginProtection()
	for _, o := range s.origins {
		_ = cop.AddTrustedOrigin(o) // validated in New
	}
	cop.SetDenyHandler(http.HandlerFunc(s.crossOriginDenied))

	r.Group(func(r chi.Router) {
		r.Use(cop.Handler, s.sessions.LoadAndSave, s.csrf)
		r.Get("/setup", s.handleSetupForm)
		r.Post("/setup", s.handleSetup)
		r.Get("/login", s.handleLoginForm)
		r.Post("/login", s.handleLogin)

		r.Group(func(r chi.Router) {
			r.Use(s.requireUser)
			r.Post("/logout", s.handleLogout)
			r.Get("/", s.handleDashboard)
			r.Get("/cas", s.handleCAList)
			r.Get("/cas/new", s.handleCANew)
			r.Post("/cas", s.handleCACreate)
			r.Get("/certs", s.handleCertList)
			r.Get("/certs/new", s.handleCertNew)
			r.Post("/certs", s.handleCertCreate)
			r.Get("/certs/{id}", s.handleCertView)
			r.Post("/certs/{id}/export", s.handleExport)
			r.Post("/certs/{id}/revoke", s.handleRevoke)
			r.Post("/certs/{id}/cancel-revoke", s.handleCancelRevoke)
			r.Get("/import", s.handleImportForm)
			r.Post("/import", s.handleImport)
			r.Get("/audit", s.handleAudit)
			r.Get("/settings", s.handleSettings)
			r.Post("/settings/password", s.handlePassword)
			r.Post("/settings/totp/start", s.handleTOTPStart)
			r.Post("/settings/totp/confirm", s.handleTOTPConfirm)
			r.Post("/settings/totp/disable", s.handleTOTPDisable)
			r.Post("/settings/backup", s.handleBackup)
		})
	})
	r.NotFound(s.sessions.LoadAndSave(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.renderStatus(w, r, http.StatusNotFound, "Page not found.")
	})).ServeHTTP)
	return r
}

// ---- middleware ----

type ctxKey int

const (
	ctxIP ctxKey = iota
	ctxUser
)

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.Error("panic", "err", v, "path", r.URL.Path, "stack", string(debug.Stack()))
				http.Error(w, "internal error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// clientIP resolves the client address. X-Forwarded-For is honoured only when
// the direct peer is a configured trusted proxy.
func (s *Server) clientIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ClientIP(r, s.cfg.TrustedProxies)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxIP, ip)))
	})
}

// ClientIP returns the client IP for r.
func ClientIP(r *http.Request, trusted []netip.Prefix) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.Unmap()
	isTrusted := func(a netip.Addr) bool {
		for _, p := range trusted {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	if !isTrusted(peer) {
		return peer.String()
	}
	// Walk X-Forwarded-For from the right, skipping trusted proxies.
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(h, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break
		}
		a = a.Unmap()
		if !isTrusted(a) {
			return a.String()
		}
	}
	return peer.String()
}

func ipOf(r *http.Request) string {
	ip, _ := r.Context().Value(ctxIP).(string)
	return ip
}

// forwardedHost uses X-Forwarded-Host as the request host, but only when the
// direct peer is a trusted proxy, so the same-origin check sees the host the
// browser actually used.
func (s *Server) forwardedHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fh := r.Header.Get("X-Forwarded-Host"); fh != "" && s.fromTrustedProxy(r) {
			host := strings.TrimSpace(strings.Split(fh, ",")[0])
			if host != "" && !strings.ContainsAny(host, "/\\ @") {
				r.Host = host
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) fromTrustedProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	peer = peer.Unmap()
	for _, p := range s.cfg.TrustedProxies {
		if p.Contains(peer) {
			return true
		}
	}
	return false
}

// crossOriginDenied explains a rejected cross-origin request, and logs the
// values needed to fix a proxy setup.
func (s *Server) crossOriginDenied(w http.ResponseWriter, r *http.Request) {
	s.log.Warn("rejected cross-origin request: if this is you, add the browser's URL to CERTLY_ALLOWED_ORIGINS or make your proxy forward the Host header",
		"origin", r.Header.Get("Origin"), "host", r.Host, "sec_fetch_site", r.Header.Get("Sec-Fetch-Site"), "path", r.URL.Path, "ip", ipOf(r))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_ = crossOriginPage.Execute(w, struct{ Origin, Host string }{r.Header.Get("Origin"), r.Host})
}

var crossOriginPage = template.Must(template.New("xo").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Request blocked · Certly</title>
<link rel="stylesheet" href="/static/pico.min.css"><link rel="stylesheet" href="/static/app.css"></head>
<body><main class="container"><article>
<h2>Request blocked</h2>
<p>Certly refused this form submission because it looks like it came from another site, which is how cross-site request forgery works.</p>
<p>The page was opened as <code>{{.Origin}}</code>, but the request arrived for host <code>{{.Host}}</code>.</p>
<p>If you opened Certly yourself, this usually means a reverse proxy or port forward changes the Host header. Fix it by either:</p>
<ul>
<li>setting <code>CERTLY_ALLOWED_ORIGINS={{.Origin}}</code> and restarting Certly, or</li>
<li>making the proxy pass the original host (nginx: <code>proxy_set_header Host $host;</code>), or listing the proxy in <code>CERTLY_TRUSTED_PROXIES</code> so its <code>X-Forwarded-Host</code> is used.</li>
</ul>
<p><a href="/">Back to Certly</a></p>
</article></main></body></html>`))

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
			"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		if s.cfg.SecureCookies {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if !strings.HasPrefix(r.URL.Path, "/static/") && !strings.HasPrefix(r.URL.Path, "/crl/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func staticCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		if strings.HasPrefix(r.URL.Path, "/static/") || r.URL.Path == "/healthz" {
			return
		}
		// Only method and path: never query strings or bodies.
		s.log.Info("http", "method", r.Method, "path", r.URL.Path, "status", sw.status,
			"ms", time.Since(start).Milliseconds(), "ip", ipOf(r))
	})
}

const (
	sessUID   = "uid"
	sessPWV   = "pwv"
	sessCSRF  = "csrf"
	sessFlash = "flash"
	sessTOTP  = "totp_pending"
)

func (s *Server) csrfToken(r *http.Request) string {
	tok := s.sessions.GetString(r.Context(), sessCSRF)
	if tok == "" {
		b := make([]byte, 32)
		_, _ = rand.Read(b)
		tok = base64.RawURLEncoding.EncodeToString(b)
		s.sessions.Put(r.Context(), sessCSRF, tok)
	}
	return tok
}

// csrf checks a per-session token on every state-changing request, on top of
// the Origin/Sec-Fetch-Site check and SameSite=Strict cookies.
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		want := s.sessions.GetString(r.Context(), sessCSRF)
		got := r.Header.Get("X-CSRF-Token")
		if got == "" {
			if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
				// The body is already capped at maxBody by limitBody.
				_ = r.ParseMultipartForm(maxBody) // #nosec G120
			}
			got = r.PostFormValue("csrf")
		}
		if want == "" || subtle.ConstantTimeCompare([]byte(want), []byte(got)) != 1 {
			s.renderStatus(w, r, http.StatusForbidden, "Your session expired or the form is stale. Reload the page and try again.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// pwVersion fingerprints a password hash so sessions die when it changes.
func pwVersion(hash string) string {
	sum := sha256.Sum256([]byte(hash))
	return hex.EncodeToString(sum[:8])
}

func (s *Server) requireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		uid := s.sessions.GetInt64(ctx, sessUID)
		if uid == 0 {
			s.redirectToLogin(w, r)
			return
		}
		u, err := s.st.UserByID(ctx, uid)
		if err != nil || subtle.ConstantTimeCompare([]byte(pwVersion(u.PasswordHash)), []byte(s.sessions.GetString(ctx, sessPWV))) != 1 {
			_ = s.sessions.Destroy(ctx)
			s.redirectToLogin(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, ctxUser, u)))
	})
}

func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	n, err := s.st.CountUsers(r.Context())
	if err == nil && n == 0 {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func userOf(r *http.Request) *store.User {
	u, _ := r.Context().Value(ctxUser).(*store.User)
	return u
}

func (s *Server) actor(r *http.Request) ca.Actor {
	name := "anonymous"
	if u := userOf(r); u != nil {
		name = u.Username
	}
	return ca.Actor{Name: name, IP: ipOf(r)}
}

func (s *Server) flash(r *http.Request, msg string) { s.sessions.Put(r.Context(), sessFlash, msg) }

// fail renders a user error on the form page or a generic 500.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ue *ca.UserError
	switch {
	case errors.As(err, &ue):
		s.renderStatus(w, r, http.StatusBadRequest, ue.Msg)
	case errors.Is(err, store.ErrNotFound):
		s.renderStatus(w, r, http.StatusNotFound, "Not found.")
	default:
		s.log.Error("request failed", "path", r.URL.Path, "err", err)
		s.renderStatus(w, r, http.StatusInternalServerError, "Something went wrong. Check the server log.")
	}
}
