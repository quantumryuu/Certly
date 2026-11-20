package web

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/quantumryuu/Certly/internal/pki"
	"github.com/quantumryuu/Certly/internal/store"
)

type pageTemplate struct {
	t *template.Template
}

var funcs = template.FuncMap{
	"date": func(t time.Time) string { return t.UTC().Format(time.DateOnly) },
	"datetime": func(t time.Time) string {
		if t.IsZero() {
			return ""
		}
		return t.UTC().Format("2006-01-02 15:04 MST")
	},
	"ptime": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format("2006-01-02 15:04 MST")
	},
	"now":      time.Now,
	"inc":      func(i int) int { return i + 1 },
	"dec":      func(i int) int { return i - 1 },
	"pemURL":   func(u string) string { return strings.TrimSuffix(u, ".crl") + ".pem" },
	"daysLeft": func(t time.Time) int { return int(time.Until(t).Hours() / 24) },
	"status":   func(c *store.Cert) string { return c.Status(time.Now()) },
	"statusClass": func(c *store.Cert) string {
		return "st-" + strings.ReplaceAll(c.Status(time.Now()), " ", "-")
	},
	"reason": func(c *store.Cert) string {
		if !c.Reason.Valid {
			return ""
		}
		return pki.ReasonLabel(int(c.Reason.Int64))
	},
	"kindLabel": kindLabel,
	"serial": func(s string) string {
		// Group hex in pairs for readability.
		var b strings.Builder
		for i, r := range s {
			if i > 0 && i%2 == 0 {
				b.WriteByte(':')
			}
			b.WriteRune(r)
		}
		return b.String()
	},
}

func kindLabel(k string) string {
	switch k {
	case "root":
		return "Root CA"
	case "intermediate":
		return "Intermediate CA"
	case "client":
		return "Client"
	case "server":
		return "Server"
	case "client-server":
		return "Client + Server"
	}
	return k
}

func loadTemplates() (map[string]*pageTemplate, error) {
	files, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	out := map[string]*pageTemplate{}
	for _, f := range files {
		name := strings.TrimSuffix(strings.TrimPrefix(f, "templates/"), ".html")
		if name == "layout" || strings.HasPrefix(name, "_") {
			continue
		}
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(templateFS, "templates/layout.html", "templates/_partials.html", f)
		if err != nil {
			return nil, fmt.Errorf("web: parse %s: %w", f, err)
		}
		out[name] = &pageTemplate{t: t}
	}
	return out, nil
}

// page is the data every template gets.
type page struct {
	Title   string
	Nav     string
	User    *store.User
	CSRF    string
	Flash   string
	Error   string
	Version string
	Data    any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name, title, nav string, data any, errMsg string) {
	pt, ok := s.pages[name]
	if !ok {
		s.log.Error("missing template", "name", name)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	p := page{Title: title, Nav: nav, User: userOf(r), CSRF: s.csrfToken(r), Error: errMsg, Version: s.cfg.Version, Data: data}
	p.Flash = s.sessions.PopString(r.Context(), sessFlash)
	var buf bytes.Buffer
	if err := pt.t.Execute(&buf, p); err != nil {
		s.log.Error("render", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// renderPartial renders one named block of a page, for HTMX swaps.
func (s *Server) renderPartial(w http.ResponseWriter, r *http.Request, name, block string, data any) {
	pt, ok := s.pages[name]
	if !ok {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := pt.t.ExecuteTemplate(&buf, block, page{Data: data, User: userOf(r)}); err != nil {
		s.log.Error("render partial", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Vary", "HX-Request")
	_, _ = buf.WriteTo(w)
}

func (s *Server) renderStatus(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.render(w, r, status, "error", http.StatusText(status), "", nil, msg)
}
