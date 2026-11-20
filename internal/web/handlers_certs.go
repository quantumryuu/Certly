package web

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/quantumryuu/Certly/internal/ca"
	"github.com/quantumryuu/Certly/internal/pki"
	"github.com/quantumryuu/Certly/internal/store"
)

const day = 24 * time.Hour

// ---- public CRL ----

func (s *Server) handleCRL(w http.ResponseWriter, r *http.Request) {
	file := chi.URLParam(r, "file")
	idStr, ext, ok := strings.Cut(file, ".")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if !ok || err != nil || id <= 0 || (ext != "crl" && ext != "pem") {
		http.NotFound(w, r)
		return
	}
	der, err := s.svc.CRL(r.Context(), id)
	if err != nil {
		var ue *ca.UserError
		if errors.Is(err, store.ErrNotFound) || errors.As(err, &ue) {
			http.NotFound(w, r)
			return
		}
		s.log.Error("serve CRL", "ca", id, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	if ext == "pem" {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_ = pem.Encode(w, &pem.Block{Type: "X509 CRL", Bytes: der})
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	_, _ = w.Write(der)
}

// ---- dashboard ----

type dashboardData struct {
	Stats    store.Stats
	Expiring []*store.Cert
	CAs      []*store.Cert
	Audit    []store.AuditEntry
	BaseURL  string
	Insecure bool
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now()
	st, err := s.st.GetStats(ctx, now)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	exp, err := s.st.Expiring(ctx, now, 30*day)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cas, err := s.st.ListCerts(ctx, store.CertFilter{CAs: true}, now)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	audit, err := s.st.ListAudit(ctx, 0, 10, 0)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "dashboard", "Dashboard", "dashboard", dashboardData{
		Stats: st, Expiring: exp, CAs: cas, Audit: audit, BaseURL: s.cfg.BaseURL,
		Insecure: !s.cfg.SecureCookies,
	}, "")
}

// ---- lists ----

type listData struct {
	Certs  []*store.Cert
	Search string
	Status string
}

func (s *Server) handleCAList(w http.ResponseWriter, r *http.Request) {
	cas, err := s.st.ListCerts(r.Context(), store.CertFilter{CAs: true}, time.Now())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "cas", "Certificate authorities", "cas", listData{Certs: cas}, "")
}

func (s *Server) handleCertList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.CertFilter{Search: q.Get("q"), Status: q.Get("status")}
	if id, err := strconv.ParseInt(q.Get("issuer"), 10, 64); err == nil {
		f.IssuerID = id
	}
	certs, err := s.st.ListCerts(r.Context(), f, time.Now())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := listData{Certs: certs, Search: f.Search, Status: f.Status}
	// HTMX live search swaps only the table.
	if r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-Target") == "cert-table" {
		s.renderPartial(w, r, "certs", "certtable", d)
		return
	}
	s.render(w, r, http.StatusOK, "certs", "Certificates", "certs", d, "")
}

// ---- forms ----

type formData struct {
	Kind      string
	IssuerID  int64
	CN        string
	O, OU     string
	C, ST, L  string
	DNS, IPs  string
	Emails    string
	URIs      string
	KeyType   string
	Days      int
	PathLen   int
	Notes     string
	CSR       string
	Issuers   []*store.Cert
	KeyTypes  []pki.KeyType
	RenewFrom *store.Cert
}

func (s *Server) issuers(r *http.Request, forCA bool) ([]*store.Cert, error) {
	cas, err := s.st.ListCerts(r.Context(), store.CertFilter{CAs: true}, time.Now())
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var out []*store.Cert
	for _, c := range cas {
		if !c.Usable(now) {
			continue
		}
		if forCA {
			// Skip CAs with pathlen 0: they can't sign intermediates.
			if pc, err := x509.ParseCertificate(c.DER); err == nil && pc.MaxPathLenZero {
				continue
			}
		}
		out = append(out, c)
	}
	return out, nil
}

func (s *Server) handleCANew(w http.ResponseWriter, r *http.Request) {
	iss, err := s.issuers(r, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := formData{Kind: "root", Days: 3650, PathLen: 1, KeyType: string(pki.KeyECDSAP256), Issuers: iss, KeyTypes: pki.KeyTypes}
	if id, err := strconv.ParseInt(r.URL.Query().Get("issuer"), 10, 64); err == nil && id > 0 {
		d.Kind, d.IssuerID, d.Days, d.PathLen = "intermediate", id, 1825, 0
	}
	s.render(w, r, http.StatusOK, "ca_new", "New CA", "cas", d, "")
}

func (s *Server) handleCertNew(w http.ResponseWriter, r *http.Request) {
	iss, err := s.issuers(r, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := formData{Kind: "client", Days: 365, KeyType: string(pki.KeyECDSAP256), Issuers: iss, KeyTypes: pki.KeyTypes}
	// Prefer an intermediate as the default issuer.
	for _, c := range iss {
		if c.Kind == "intermediate" {
			d.IssuerID = c.ID
			break
		}
	}
	q := r.URL.Query()
	if id, err := strconv.ParseInt(q.Get("issuer"), 10, 64); err == nil {
		d.IssuerID = id
	}
	if id, err := strconv.ParseInt(q.Get("renew"), 10, 64); err == nil {
		old, err := s.st.CertByID(r.Context(), id)
		if err == nil && !old.IsCA() {
			if pc, err := x509.ParseCertificate(old.DER); err == nil {
				d.Kind, d.KeyType, d.RenewFrom = old.Kind, old.KeyType, old
				d.IssuerID = old.IssuerID.Int64
				d.CN = pc.Subject.CommonName
				d.O, d.OU = first(pc.Subject.Organization), first(pc.Subject.OrganizationalUnit)
				d.C, d.ST, d.L = first(pc.Subject.Country), first(pc.Subject.Province), first(pc.Subject.Locality)
				d.DNS = strings.Join(pc.DNSNames, "\n")
				var ips []string
				for _, ip := range pc.IPAddresses {
					ips = append(ips, ip.String())
				}
				d.IPs = strings.Join(ips, "\n")
				d.Emails = strings.Join(pc.EmailAddresses, "\n")
				var uris []string
				for _, u := range pc.URIs {
					uris = append(uris, u.String())
				}
				d.URIs = strings.Join(uris, "\n")
				d.Days = int(pc.NotAfter.Sub(pc.NotBefore).Hours()/24 + 0.5)
				d.Notes = "Renewal of #" + strconv.FormatInt(old.ID, 10)
			}
		}
	}
	s.render(w, r, http.StatusOK, "cert_new", "New certificate", "certs", d, "")
}

func first(s []string) string {
	if len(s) > 0 {
		return s[0]
	}
	return ""
}

func splitList(s string) []string {
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t' })
	seen := map[string]bool{}
	var out []string
	for _, v := range f {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func readForm(r *http.Request) formData {
	atoi := func(k string, def int) int {
		v, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue(k)))
		if err != nil {
			return def
		}
		return v
	}
	issuer, _ := strconv.ParseInt(r.PostFormValue("issuer_id"), 10, 64)
	return formData{
		Kind: r.PostFormValue("kind"), IssuerID: issuer,
		CN: strings.TrimSpace(r.PostFormValue("cn")), O: strings.TrimSpace(r.PostFormValue("o")), OU: strings.TrimSpace(r.PostFormValue("ou")),
		C: strings.ToUpper(strings.TrimSpace(r.PostFormValue("c"))), ST: strings.TrimSpace(r.PostFormValue("st")), L: strings.TrimSpace(r.PostFormValue("l")),
		DNS: r.PostFormValue("dns"), IPs: r.PostFormValue("ips"), Emails: r.PostFormValue("emails"), URIs: r.PostFormValue("uris"),
		KeyType: r.PostFormValue("key_type"), Days: atoi("days", 0), PathLen: atoi("pathlen", -1),
		Notes: r.PostFormValue("notes"), CSR: r.PostFormValue("csr"),
	}
}

func (d formData) request() (pki.Request, error) {
	req := pki.Request{
		Kind:     pki.Kind(d.Kind),
		Subject:  pki.Subject{CommonName: d.CN, Organization: d.O, OrganizationalUnit: d.OU, Country: d.C, Province: d.ST, Locality: d.L},
		KeyType:  pki.KeyType(d.KeyType),
		Validity: time.Duration(d.Days) * day,
		PathLen:  d.PathLen,
	}
	if d.Days < 1 {
		return req, &ca.UserError{Msg: "Validity must be at least 1 day."}
	}
	if len(d.Notes) > 1000 {
		return req, &ca.UserError{Msg: "Notes must be at most 1000 characters."}
	}
	for _, f := range []string{d.O, d.OU, d.ST, d.L} {
		if len(f) > 64 {
			return req, &ca.UserError{Msg: "Subject fields must be at most 64 characters."}
		}
	}
	req.SANs.DNSNames = splitList(strings.ToLower(d.DNS))
	for _, v := range splitList(d.IPs) {
		ip := net.ParseIP(v)
		if ip == nil {
			return req, &ca.UserError{Msg: fmt.Sprintf("Invalid IP address %q.", v)}
		}
		req.SANs.IPs = append(req.SANs.IPs, ip)
	}
	req.SANs.Emails = splitList(d.Emails)
	for _, v := range splitList(d.URIs) {
		u, err := url.Parse(v)
		if err != nil || u.Scheme == "" {
			return req, &ca.UserError{Msg: fmt.Sprintf("Invalid URI %q (needs a scheme, e.g. spiffe://).", v)}
		}
		req.SANs.URIs = append(req.SANs.URIs, u)
	}
	total := len(req.SANs.DNSNames) + len(req.SANs.IPs) + len(req.SANs.Emails) + len(req.SANs.URIs)
	if total > 100 {
		return req, &ca.UserError{Msg: "At most 100 subject alternative names."}
	}
	return req, nil
}

func (s *Server) handleCACreate(w http.ResponseWriter, r *http.Request) {
	d := readForm(r)
	rerender := func(msg string) {
		d.Issuers, _ = s.issuers(r, true)
		d.KeyTypes = pki.KeyTypes
		s.render(w, r, http.StatusBadRequest, "ca_new", "New CA", "cas", d, msg)
	}
	if d.Kind != "root" && d.Kind != "intermediate" {
		rerender("Choose root or intermediate.")
		return
	}
	if d.Kind == "root" {
		d.IssuerID = 0
	}
	if d.PathLen < -1 || d.PathLen > 5 {
		rerender("Path length must be between 0 and 5, or unlimited.")
		return
	}
	req, err := d.request()
	if err == nil {
		var c *store.Cert
		c, err = s.svc.Issue(r.Context(), s.actor(r), ca.IssueInput{Request: req, IssuerID: d.IssuerID, Notes: d.Notes})
		if err == nil {
			s.flash(r, kindLabel(c.Kind)+" created.")
			http.Redirect(w, r, "/certs/"+strconv.FormatInt(c.ID, 10), http.StatusSeeOther)
			return
		}
	}
	var ue *ca.UserError
	if errors.As(err, &ue) {
		rerender(ue.Msg)
		return
	}
	s.fail(w, r, err)
}

func (s *Server) handleCertCreate(w http.ResponseWriter, r *http.Request) {
	d := readForm(r)
	rerender := func(msg string) {
		d.Issuers, _ = s.issuers(r, false)
		d.KeyTypes = pki.KeyTypes
		s.render(w, r, http.StatusBadRequest, "cert_new", "New certificate", "certs", d, msg)
	}
	switch d.Kind {
	case "client", "server", "client-server":
	default:
		rerender("Choose a certificate type.")
		return
	}
	req, err := d.request()
	if err == nil {
		csrPEM := []byte(strings.TrimSpace(d.CSR))
		if f, _, ferr := r.FormFile("csr_file"); ferr == nil {
			data, rerr := io.ReadAll(io.LimitReader(f, pki.MaxPEMInput+1))
			_ = f.Close()
			if rerr == nil && len(data) > 0 {
				csrPEM = data
			}
		}
		if len(csrPEM) > 0 {
			csr, perr := pki.ParseCSR(csrPEM)
			if perr != nil {
				rerender(strings.TrimPrefix(perr.Error(), "pki: "))
				return
			}
			req.PublicKey = csr.PublicKey
		}
		var c *store.Cert
		c, err = s.svc.Issue(r.Context(), s.actor(r), ca.IssueInput{Request: req, IssuerID: d.IssuerID, Notes: d.Notes})
		if err == nil {
			s.flash(r, "Certificate issued.")
			http.Redirect(w, r, "/certs/"+strconv.FormatInt(c.ID, 10), http.StatusSeeOther)
			return
		}
	}
	var ue *ca.UserError
	if errors.As(err, &ue) {
		rerender(ue.Msg)
		return
	}
	s.fail(w, r, err)
}

// ---- view ----

type viewData struct {
	Cert        *store.Cert
	X509        *x509.Certificate
	Fingerprint string
	PEM         string
	Formats     []pki.Format
	Reasons     []struct {
		Code  int
		Label string
	}
	Children []*store.Cert
	Audit    []store.AuditEntry
	CRLURL   string
	CanSign  bool
}

func (s *Server) certFromURL(r *http.Request) (*store.Cert, error) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		return nil, store.ErrNotFound
	}
	return s.st.CertByID(r.Context(), id)
}

func (s *Server) viewPage(w http.ResponseWriter, r *http.Request, status int, c *store.Cert, errMsg string) {
	pc, err := x509.ParseCertificate(c.DER)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sum := sha256.Sum256(c.DER)
	d := viewData{Cert: c, X509: pc, Fingerprint: strings.ToUpper(hex.EncodeToString(sum[:])), PEM: string(pki.CertPEM(pc)),
		Reasons: pki.Reasons, CanSign: c.Usable(time.Now())}
	for _, f := range pki.Formats {
		if f.NeedsKey && !c.HasKey() {
			continue
		}
		if f.ID == "chain-pem" && !c.IssuerID.Valid {
			continue
		}
		d.Formats = append(d.Formats, f)
	}
	if c.IsCA() {
		d.CRLURL = s.svc.CRLURL(c.ID)
		d.Children, _ = s.st.ListCerts(r.Context(), store.CertFilter{IssuerID: c.ID}, time.Now())
		inter, _ := s.st.ListCerts(r.Context(), store.CertFilter{CAs: true, IssuerID: c.ID}, time.Now())
		d.Children = append(inter, d.Children...)
	}
	d.Audit, _ = s.st.ListAudit(r.Context(), c.ID, 20, 0)
	s.render(w, r, status, "cert_view", c.CommonName, navFor(c), d, errMsg)
}

func navFor(c *store.Cert) string {
	if c.IsCA() {
		return "cas"
	}
	return "certs"
}

func (s *Server) handleCertView(w http.ResponseWriter, r *http.Request) {
	c, err := s.certFromURL(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.viewPage(w, r, http.StatusOK, c, "")
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	c, err := s.certFromURL(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pw := r.PostFormValue("password")
	if pw != r.PostFormValue("password2") {
		s.viewPage(w, r, http.StatusBadRequest, c, "The export passwords don't match.")
		return
	}
	opt := pki.ExportOptions{Password: pw, IncludeKey: r.PostFormValue("include_key") == "on"}
	f, err := s.svc.Export(r.Context(), s.actor(r), c.ID, r.PostFormValue("format"), opt)
	if err != nil {
		var ue *ca.UserError
		if errors.As(err, &ue) {
			s.viewPage(w, r, http.StatusBadRequest, c, ue.Msg)
			return
		}
		s.fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", f.ContentType)
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": f.Name}))
	w.Header().Set("Content-Length", strconv.Itoa(len(f.Data)))
	// A download with a fixed non-HTML type, attachment disposition, nosniff and CSP: not renderable.
	_, _ = w.Write(f.Data) // #nosec G705
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	c, err := s.certFromURL(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if r.PostFormValue("confirm") != "on" {
		s.viewPage(w, r, http.StatusBadRequest, c, "Tick the confirmation box to revoke.")
		return
	}
	reason, _ := strconv.Atoi(r.PostFormValue("reason"))
	var at time.Time
	if r.PostFormValue("when") == "scheduled" {
		at, err = time.ParseInLocation("2006-01-02T15:04", r.PostFormValue("at"), time.UTC)
		if err != nil {
			s.viewPage(w, r, http.StatusBadRequest, c, "Pick a valid date and time (UTC) for the scheduled revocation.")
			return
		}
		if !at.After(time.Now()) {
			s.viewPage(w, r, http.StatusBadRequest, c, "The scheduled time must be in the future. Use “now” to revoke immediately.")
			return
		}
	}
	if err := s.svc.Revoke(r.Context(), s.actor(r), c.ID, at, reason); err != nil {
		var ue *ca.UserError
		if errors.As(err, &ue) {
			s.viewPage(w, r, http.StatusBadRequest, c, ue.Msg)
			return
		}
		s.fail(w, r, err)
		return
	}
	if at.IsZero() {
		s.flash(r, "Certificate revoked. The CRL has been updated.")
	} else {
		s.flash(r, "Revocation scheduled for "+at.Format("2006-01-02 15:04")+" UTC.")
	}
	http.Redirect(w, r, "/certs/"+strconv.FormatInt(c.ID, 10), http.StatusSeeOther)
}

func (s *Server) handleCancelRevoke(w http.ResponseWriter, r *http.Request) {
	c, err := s.certFromURL(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.svc.CancelRevoke(r.Context(), s.actor(r), c.ID); err != nil {
		s.fail(w, r, err)
		return
	}
	s.flash(r, "Scheduled revocation cancelled.")
	http.Redirect(w, r, "/certs/"+strconv.FormatInt(c.ID, 10), http.StatusSeeOther)
}

// ---- import ----

func formFileOrText(r *http.Request, fileField, textField string) []byte {
	if f, _, err := r.FormFile(fileField); err == nil {
		data, err := io.ReadAll(io.LimitReader(f, pki.MaxPEMInput+1))
		_ = f.Close()
		if err == nil && len(data) > 0 {
			return data
		}
	}
	return []byte(strings.TrimSpace(r.PostFormValue(textField)))
}

func (s *Server) handleImportForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "import", "Import", "import", nil, "")
}

func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	certPEM := formFileOrText(r, "cert_file", "cert")
	keyPEM := formFileOrText(r, "key_file", "key")
	if len(certPEM) == 0 {
		s.render(w, r, http.StatusBadRequest, "import", "Import", "import", nil, "Paste or upload a certificate.")
		return
	}
	c, err := s.svc.Import(r.Context(), s.actor(r), certPEM, keyPEM, []byte(r.PostFormValue("key_password")), r.PostFormValue("notes"))
	if err != nil {
		var ue *ca.UserError
		if errors.As(err, &ue) {
			s.render(w, r, http.StatusBadRequest, "import", "Import", "import", nil, ue.Msg)
			return
		}
		s.fail(w, r, err)
		return
	}
	s.flash(r, kindLabel(c.Kind)+" imported.")
	http.Redirect(w, r, "/certs/"+strconv.FormatInt(c.ID, 10), http.StatusSeeOther)
}

// ---- audit ----

type auditData struct {
	Entries []store.AuditEntry
	Page    int
	Next    bool
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	const per = 100
	p, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if p < 1 {
		p = 1
	}
	if p > 10000 {
		p = 10000
	}
	entries, err := s.st.ListAudit(r.Context(), 0, per+1, (p-1)*per)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := auditData{Page: p, Next: len(entries) > per}
	if d.Next {
		entries = entries[:per]
	}
	d.Entries = entries
	s.render(w, r, http.StatusOK, "audit", "Audit log", "audit", d, "")
}
