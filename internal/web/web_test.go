package web

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"software.sslmate.com/src/go-pkcs12"

	"github.com/quantumryuu/Certly/internal/ca"
	certcrypto "github.com/quantumryuu/Certly/internal/crypto"
	"github.com/quantumryuu/Certly/internal/store"
)

const adminPW = "correct horse battery"

type env struct {
	t   *testing.T
	ts  *httptest.Server
	st  *store.Store
	c   *http.Client
	svc *ca.Service
}

func newEnv(t *testing.T) *env { return newEnvBase(t, true) }

// newEnvBase starts a server; withBase sets CERTLY_BASE_URL to the test URL.
func newEnvBase(t *testing.T, withBase bool) *env { return newEnvCfg(t, withBase, nil) }

func newEnvCfg(t *testing.T, withBase bool, tweak func(*Config)) *env {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "certly.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e, _ := certcrypto.New(bytes.Repeat([]byte{3}, certcrypto.KeySize))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &ca.Service{Store: st, Env: e, CRLValidity: 7 * 24 * time.Hour, Log: log}
	ts := httptest.NewUnstartedServer(nil)
	ts.Start()
	t.Cleanup(ts.Close)
	base := ""
	if withBase {
		base = ts.URL
	}
	svc.BaseURL = base
	cfg := Config{BaseURL: base, DataDir: t.TempDir(), Version: "test"}
	if tweak != nil {
		tweak(&cfg)
	}
	srv, err := New(cfg, svc, log)
	if err != nil {
		t.Fatal(err)
	}
	ts.Config.Handler = srv.Handler()
	return &env{t: t, ts: ts, st: st, c: client(), svc: svc}
}

func client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (e *env) do(c *http.Client, method, path string, form url.Values, hdr map[string]string) (*http.Response, string) {
	e.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (e *env) csrf(c *http.Client, path string) string {
	e.t.Helper()
	_, body := e.do(c, "GET", path, nil, nil)
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		e.t.Fatalf("no CSRF token on %s", path)
	}
	return m[1]
}

// post fetches a CSRF token from tokenPage, then posts the form.
func (e *env) post(c *http.Client, tokenPage, path string, form url.Values) (*http.Response, string) {
	e.t.Helper()
	form.Set("csrf", e.csrf(c, tokenPage))
	return e.do(c, "POST", path, form, nil)
}

func (e *env) setup() {
	e.t.Helper()
	resp, _ := e.post(e.c, "/setup", "/setup", url.Values{"username": {"admin"}, "password": {adminPW}, "password2": {adminPW}})
	if resp.StatusCode != http.StatusSeeOther {
		e.t.Fatalf("setup: %d", resp.StatusCode)
	}
}

func idFrom(t *testing.T, resp *http.Response) int64 {
	t.Helper()
	loc := resp.Header.Get("Location")
	id, err := strconv.ParseInt(strings.TrimPrefix(loc, "/certs/"), 10, 64)
	if resp.StatusCode != http.StatusSeeOther || err != nil {
		t.Fatalf("expected redirect to /certs/ID, got %d %q", resp.StatusCode, loc)
	}
	return id
}

func (e *env) createChain() (root, inter int64) {
	e.t.Helper()
	resp, body := e.post(e.c, "/cas/new", "/cas", url.Values{"kind": {"root"}, "cn": {"Lab Root"}, "key_type": {"ecdsa-p256"}, "days": {"3650"}, "pathlen": {"1"}})
	if resp.StatusCode != http.StatusSeeOther {
		e.t.Fatalf("create root: %d %s", resp.StatusCode, body)
	}
	root = idFrom(e.t, resp)
	resp, body = e.post(e.c, "/cas/new", "/cas", url.Values{"kind": {"intermediate"}, "issuer_id": {strconv.FormatInt(root, 10)}, "cn": {"Lab Intermediate"}, "key_type": {"ecdsa-p256"}, "days": {"1825"}, "pathlen": {"0"}})
	if resp.StatusCode != http.StatusSeeOther {
		e.t.Fatalf("create intermediate: %d %s", resp.StatusCode, body)
	}
	return root, idFrom(e.t, resp)
}

func TestSetupFlow(t *testing.T) {
	e := newEnv(t)
	resp, _ := e.do(e.c, "GET", "/", nil, nil)
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/setup" {
		t.Fatalf("fresh install should redirect to setup, got %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// Weak password rejected.
	resp, _ = e.post(e.c, "/setup", "/setup", url.Values{"username": {"admin"}, "password": {"short"}, "password2": {"short"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("weak password: %d", resp.StatusCode)
	}
	e.setup()
	resp, _ = e.do(e.c, "GET", "/", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dashboard after setup: %d", resp.StatusCode)
	}
	// A second setup must not create another admin, even with a fresh client.
	other := client()
	resp, _ = e.do(other, "GET", "/setup", nil, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("setup page reachable after setup: %d", resp.StatusCode)
	}
	if n, _ := e.st.CountUsers(context.Background()); n != 1 {
		t.Fatalf("%d users", n)
	}
}

func TestAuthRequired(t *testing.T) {
	e := newEnv(t)
	e.setup()
	anon := client()
	for _, p := range []string{"/", "/cas", "/certs", "/certs/1", "/audit", "/settings", "/import", "/cas/new", "/certs/new"} {
		resp, _ := e.do(anon, "GET", p, nil, nil)
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
			t.Fatalf("GET %s without login: %d %s", p, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	// A POST with a valid CSRF token for an anonymous session still needs a login.
	tok := e.csrf(anon, "/login")
	for _, p := range []string{"/cas", "/certs", "/certs/1/export", "/certs/1/revoke", "/settings/backup", "/import"} {
		resp, _ := e.do(anon, "POST", p, url.Values{"csrf": {tok}}, nil)
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
			t.Fatalf("POST %s without login: %d", p, resp.StatusCode)
		}
	}
	resp, body := e.do(anon, "GET", "/healthz", nil, nil)
	if resp.StatusCode != 200 || body != "ok\n" {
		t.Fatalf("healthz: %d %q", resp.StatusCode, body)
	}
}

func TestCSRFAndCrossOrigin(t *testing.T) {
	e := newEnv(t)
	e.setup()
	form := url.Values{"kind": {"root"}, "cn": {"x"}, "key_type": {"ecdsa-p256"}, "days": {"10"}, "pathlen": {"0"}}
	resp, _ := e.do(e.c, "POST", "/cas", form, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST without CSRF token: %d", resp.StatusCode)
	}
	form.Set("csrf", "forged")
	resp, _ = e.do(e.c, "POST", "/cas", form, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST with forged token: %d", resp.StatusCode)
	}
	form.Set("csrf", e.csrf(e.c, "/cas/new"))
	for name, hdr := range map[string]map[string]string{
		"origin":         {"Origin": "http://evil.example"},
		"sec-fetch-site": {"Sec-Fetch-Site": "cross-site"},
	} {
		resp, _ = e.do(e.c, "POST", "/cas", form, hdr)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("cross-origin (%s) POST: %d", name, resp.StatusCode)
		}
	}
	if cas, _ := e.st.ListCerts(context.Background(), store.CertFilter{CAs: true}, time.Now()); len(cas) != 0 {
		t.Fatal("a forged request created a CA")
	}
}

func TestLoginRateLimitAndSessions(t *testing.T) {
	e := newEnv(t)
	e.setup()
	attacker := client()
	for i := 0; i < 5; i++ {
		resp, _ := e.post(attacker, "/login", "/login", url.Values{"username": {"admin"}, "password": {"wrong password " + strconv.Itoa(i)}})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, resp.StatusCode)
		}
	}
	// Even the right password is refused while locked out.
	resp, _ := e.post(attacker, "/login", "/login", url.Values{"username": {"admin"}, "password": {adminPW}})
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("locked login: %d", resp.StatusCode)
	}
	log, _ := e.st.ListAudit(context.Background(), 0, 50, 0)
	fails := 0
	for _, l := range log {
		if l.Action == "login-failed" {
			fails++
			if strings.Contains(l.Detail, "wrong password") {
				t.Fatal("password in audit log")
			}
		}
	}
	if fails != 5 {
		t.Fatalf("%d failed logins audited", fails)
	}
}

func TestSessionLifecycle(t *testing.T) {
	e := newEnv(t)
	e.setup()
	// Second browser logs in.
	b2 := client()
	resp, _ := e.post(b2, "/login", "/login", url.Values{"username": {"admin"}, "password": {adminPW}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	u, _ := url.Parse(e.ts.URL)
	preLogin := client()
	e.do(preLogin, "GET", "/login", nil, nil)
	before := preLogin.Jar.Cookies(u)
	e.post(preLogin, "/login", "/login", url.Values{"username": {"admin"}, "password": {adminPW}})
	after := preLogin.Jar.Cookies(u)
	if len(before) == 0 || len(after) == 0 || before[0].Value == after[0].Value {
		t.Fatal("session token not renewed on login (fixation)")
	}

	// Password change in browser 1 kills browser 2's session.
	newPW := "another long password"
	resp, _ = e.post(e.c, "/settings", "/settings/password", url.Values{"current_password": {adminPW}, "password": {newPW}, "password2": {newPW}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("password change: %d", resp.StatusCode)
	}
	resp, _ = e.do(b2, "GET", "/", nil, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("old session survived password change: %d", resp.StatusCode)
	}
	resp, _ = e.do(e.c, "GET", "/", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("current session lost after password change: %d", resp.StatusCode)
	}

	// Logout: the old cookie no longer works.
	cookies := e.c.Jar.Cookies(u)
	e.post(e.c, "/", "/logout", url.Values{})
	replay := client()
	replay.Jar.SetCookies(u, cookies)
	resp, _ = e.do(replay, "GET", "/", nil, nil)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("session replay after logout: %d", resp.StatusCode)
	}
}

func TestIssueExportRevokeCRL(t *testing.T) {
	e := newEnv(t)
	e.setup()
	_, inter := e.createChain()
	resp, body := e.post(e.c, "/certs/new", "/certs", url.Values{"kind": {"client"}, "issuer_id": {strconv.FormatInt(inter, 10)},
		"cn": {"laptop"}, "emails": {"me@example.com"}, "key_type": {"ecdsa-p256"}, "days": {"90"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("issue: %d %s", resp.StatusCode, body)
	}
	leaf := idFrom(t, resp)
	path := "/certs/" + strconv.FormatInt(leaf, 10)
	resp, _ = e.do(e.c, "GET", path, nil, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("view: %d", resp.StatusCode)
	}

	// P12 export.
	resp, body = e.post(e.c, path, path+"/export", url.Values{"format": {"p12"}, "password": {"export-pass"}, "password2": {"export-pass"}})
	if resp.StatusCode != 200 || !strings.Contains(resp.Header.Get("Content-Disposition"), `filename=laptop.p12`) {
		t.Fatalf("p12 export: %d %s", resp.StatusCode, resp.Header.Get("Content-Disposition"))
	}
	_, cert, cas, err := pkcs12.DecodeChain([]byte(body), "export-pass")
	if err != nil || cert.Subject.CommonName != "laptop" || len(cas) != 2 {
		t.Fatalf("p12 decode: %v", err)
	}
	// Mismatched confirmation.
	resp, _ = e.post(e.c, path, path+"/export", url.Values{"format": {"p12"}, "password": {"export-pass"}, "password2": {"typo"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("mismatched password export: %d", resp.StatusCode)
	}

	// Revoke without confirmation is refused, then revoke.
	resp, _ = e.post(e.c, path, path+"/revoke", url.Values{"when": {"now"}, "reason": {"1"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("revoke without confirm: %d", resp.StatusCode)
	}
	resp, _ = e.post(e.c, path, path+"/revoke", url.Values{"when": {"now"}, "reason": {"1"}, "confirm": {"on"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}

	// The CRL is public and lists the serial.
	anon := client()
	crlPath := "/crl/" + strconv.FormatInt(inter, 10)
	resp, body = e.do(anon, "GET", crlPath+".crl", nil, nil)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/pkix-crl" {
		t.Fatalf("crl: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	crl, err := x509.ParseRevocationList([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := e.st.CertByID(context.Background(), leaf)
	want, _ := new(big.Int).SetString(stored.Serial, 16)
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(want) != 0 {
		t.Fatal("revoked serial not in public CRL")
	}
	_, body = e.do(anon, "GET", crlPath+".pem", nil, nil)
	if b, _ := pem.Decode([]byte(body)); b == nil || b.Type != "X509 CRL" {
		t.Fatal("PEM CRL malformed")
	}
	for _, p := range []string{"/crl/999.crl", "/crl/abc.crl", "/crl/1.txt", "/crl/" + strconv.FormatInt(leaf, 10) + ".crl"} {
		if resp, _ := e.do(anon, "GET", p, nil, nil); resp.StatusCode != 404 {
			t.Fatalf("GET %s: %d", p, resp.StatusCode)
		}
	}
}

func TestScheduleRevokeForm(t *testing.T) {
	e := newEnv(t)
	e.setup()
	_, inter := e.createChain()
	resp, _ := e.post(e.c, "/certs/new", "/certs", url.Values{"kind": {"server"}, "issuer_id": {strconv.FormatInt(inter, 10)}, "cn": {"nas"}, "dns": {"nas.lan"}, "key_type": {"ecdsa-p256"}, "days": {"90"}})
	leaf := idFrom(t, resp)
	path := "/certs/" + strconv.FormatInt(leaf, 10)
	at := time.Now().UTC().Add(48 * time.Hour).Format("2006-01-02T15:04")
	resp, _ = e.post(e.c, path, path+"/revoke", url.Values{"when": {"scheduled"}, "at": {at}, "reason": {"4"}, "confirm": {"on"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("schedule: %d", resp.StatusCode)
	}
	c, _ := e.st.CertByID(context.Background(), leaf)
	if c.RevokeAt == nil || c.RevokedAt != nil {
		t.Fatalf("not scheduled: %+v", c)
	}
	past := time.Now().UTC().Add(-time.Hour).Format("2006-01-02T15:04")
	resp, _ = e.post(e.c, path, path+"/revoke", url.Values{"when": {"scheduled"}, "at": {past}, "reason": {"4"}, "confirm": {"on"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("past schedule accepted: %d", resp.StatusCode)
	}
	resp, _ = e.post(e.c, path, path+"/cancel-revoke", url.Values{})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("cancel: %d", resp.StatusCode)
	}
}

func TestXSSEscaped(t *testing.T) {
	e := newEnv(t)
	e.setup()
	_, inter := e.createChain()
	payload := `<script>alert(1)</script>`
	resp, body := e.post(e.c, "/certs/new", "/certs", url.Values{"kind": {"client"}, "issuer_id": {strconv.FormatInt(inter, 10)},
		"cn": {payload}, "notes": {`"><img src=x onerror=alert(1)>`}, "key_type": {"ecdsa-p256"}, "days": {"1"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("issue: %d %s", resp.StatusCode, body)
	}
	for _, p := range []string{resp.Header.Get("Location"), "/certs", "/", "/audit"} {
		_, body = e.do(e.c, "GET", p, nil, nil)
		if strings.Contains(body, payload) || strings.Contains(body, "<img src=x") {
			t.Fatalf("unescaped payload on %s", p)
		}
	}
	resp, _ = e.do(e.c, "GET", "/", nil, nil)
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("CSP = %q", csp)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("missing security headers")
	}
}

func TestHTMXPartialAndSearch(t *testing.T) {
	e := newEnv(t)
	e.setup()
	_, inter := e.createChain()
	for _, cn := range []string{"alpha-laptop", "beta-phone"} {
		e.post(e.c, "/certs/new", "/certs", url.Values{"kind": {"client"}, "issuer_id": {strconv.FormatInt(inter, 10)}, "cn": {cn}, "key_type": {"ecdsa-p256"}, "days": {"30"}})
	}
	resp, body := e.do(e.c, "GET", "/certs?q=alpha", nil, map[string]string{"HX-Request": "true", "HX-Target": "cert-table"})
	if resp.StatusCode != 200 || strings.Contains(body, "<html") || !strings.Contains(body, "alpha-laptop") || strings.Contains(body, "beta-phone") {
		t.Fatalf("partial search wrong: %d %s", resp.StatusCode, body)
	}
}

func TestBodyLimit(t *testing.T) {
	e := newEnv(t)
	e.setup()
	big := url.Values{"csrf": {e.csrf(e.c, "/import")}, "cert": {strings.Repeat("A", 2<<20)}}
	resp, _ := e.do(e.c, "POST", "/import", big, nil)
	if resp.StatusCode < 400 || resp.StatusCode >= 500 {
		t.Fatalf("2 MiB body: %d", resp.StatusCode)
	}
}

func TestClientIP(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	tests := []struct {
		remote, xff, want string
	}{
		{"203.0.113.9:1234", "1.2.3.4", "203.0.113.9"},             // untrusted peer: header ignored
		{"10.0.0.2:1234", "1.2.3.4", "1.2.3.4"},                    // trusted proxy
		{"10.0.0.2:1234", "6.6.6.6, 1.2.3.4, 10.0.0.3", "1.2.3.4"}, // rightmost untrusted wins
		{"10.0.0.2:1234", "garbage", "10.0.0.2"},
	}
	for _, tc := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tc.remote
		r.Header.Set("X-Forwarded-For", tc.xff)
		if got := ClientIP(r, trusted); got != tc.want {
			t.Fatalf("%s via %q: got %s want %s", tc.remote, tc.xff, got, tc.want)
		}
	}
}

func TestWithoutBaseURL(t *testing.T) {
	e := newEnvBase(t, false)
	e.setup()
	_, inter := e.createChain()
	resp, _ := e.post(e.c, "/certs/new", "/certs", url.Values{"kind": {"client"}, "issuer_id": {strconv.FormatInt(inter, 10)}, "cn": {"dev"}, "key_type": {"ecdsa-p256"}, "days": {"30"}})
	leaf := idFrom(t, resp)
	c, _ := e.st.CertByID(context.Background(), leaf)
	pc, _ := x509.ParseCertificate(c.DER)
	if len(pc.CRLDistributionPoints) != 0 {
		t.Fatalf("CDP embedded: %v", pc.CRLDistributionPoints)
	}
	// The CA page shows the CRL URL built from the host being used.
	u, _ := url.Parse(e.ts.URL)
	_, body := e.do(e.c, "GET", "/certs/"+strconv.FormatInt(inter, 10), nil, nil)
	want := "http://" + u.Host + "/crl/" + strconv.FormatInt(inter, 10) + ".crl"
	if !strings.Contains(body, want) || !strings.Contains(body, "Not embedded in certificates") {
		t.Fatalf("CA page missing %s", want)
	}
	// Cross-origin protection still works without a configured origin.
	form := url.Values{"csrf": {e.csrf(e.c, "/cas/new")}, "kind": {"root"}, "cn": {"x"}, "key_type": {"ecdsa-p256"}, "days": {"10"}, "pathlen": {"0"}}
	resp, _ = e.do(e.c, "POST", "/cas", form, map[string]string{"Origin": "http://evil.example"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-origin POST without base URL: %d", resp.StatusCode)
	}
}

// Reproduces "Sec-Fetch-Site is missing, and Origin does not match Host":
// plain-HTTP LAN access through a proxy that rewrites Host.
func TestProxyRewritesHost(t *testing.T) {
	browser := "http://certly.lan:8080"
	proxied := map[string]string{"Origin": browser, "Host": "127.0.0.1:8080"}
	createCA := func(e *env, hdr map[string]string) int {
		form := url.Values{"csrf": {e.csrf(e.c, "/cas/new")}, "kind": {"root"}, "cn": {"x"}, "key_type": {"ecdsa-p256"}, "days": {"10"}, "pathlen": {"0"}}
		resp, body := e.do(e.c, "POST", "/cas", form, hdr)
		if resp.StatusCode == http.StatusForbidden && !strings.Contains(body, "CERTLY_ALLOWED_ORIGINS") {
			t.Fatalf("deny page is not the helpful one: %s", body)
		}
		return resp.StatusCode
	}

	t.Run("blocked by default", func(t *testing.T) {
		e := newEnvBase(t, false)
		e.setup()
		if got := createCA(e, proxied); got != http.StatusForbidden {
			t.Fatalf("got %d", got)
		}
	})
	t.Run("allowed origin", func(t *testing.T) {
		e := newEnvCfg(t, false, func(c *Config) { c.AllowedOrigins = []string{browser + "/"} })
		e.setup()
		if got := createCA(e, proxied); got != http.StatusSeeOther {
			t.Fatalf("got %d", got)
		}
		// Other origins stay blocked.
		if got := createCA(e, map[string]string{"Origin": "http://evil.example", "Host": "127.0.0.1:8080"}); got != http.StatusForbidden {
			t.Fatalf("evil origin: %d", got)
		}
	})
	t.Run("forwarded host from trusted proxy", func(t *testing.T) {
		e := newEnvCfg(t, false, func(c *Config) { c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")} })
		e.setup()
		hdr := map[string]string{"Origin": browser, "Host": "127.0.0.1:8080", "X-Forwarded-Host": "certly.lan:8080"}
		if got := createCA(e, hdr); got != http.StatusSeeOther {
			t.Fatalf("got %d", got)
		}
		// An attacker's page can't use X-Forwarded-Host to make its own origin match.
		evil := map[string]string{"Origin": "http://evil.example", "Host": "127.0.0.1:8080", "X-Forwarded-Host": "certly.lan:8080"}
		if got := createCA(e, evil); got != http.StatusForbidden {
			t.Fatalf("evil origin with forwarded host: %d", got)
		}
	})
	t.Run("forwarded host ignored from untrusted peer", func(t *testing.T) {
		e := newEnvCfg(t, false, func(c *Config) { c.TrustedProxies = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")} })
		e.setup()
		hdr := map[string]string{"Origin": "http://evil.example", "Host": "127.0.0.1:8080", "X-Forwarded-Host": "evil.example"}
		if got := createCA(e, hdr); got != http.StatusForbidden {
			t.Fatalf("spoofed X-Forwarded-Host from untrusted peer: %d", got)
		}
	})
}

func TestNormalizeOrigin(t *testing.T) {
	for in, want := range map[string]string{"https://certly.lan/": "https://certly.lan", "http://10.0.0.5:8080": "http://10.0.0.5:8080"} {
		if got, err := NormalizeOrigin(in); err != nil || got != want {
			t.Fatalf("%s: %s %v", in, got, err)
		}
	}
	for _, bad := range []string{"certly.lan", "ftp://x", "https://x/path", "https://u@x", "*"} {
		if _, err := NormalizeOrigin(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
