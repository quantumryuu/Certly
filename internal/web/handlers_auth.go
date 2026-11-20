package web

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"html/template"
	"image/png"
	"net/http"
	"strings"
	"time"

	"github.com/pquerna/otp"

	"github.com/quantumryuu/Certly/internal/auth"
	"github.com/quantumryuu/Certly/internal/backup"
	"github.com/quantumryuu/Certly/internal/ca"
)

var usernameOK = func(u string) bool {
	if len(u) < 1 || len(u) > 64 {
		return false
	}
	for _, r := range u {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == '@') {
			return false
		}
	}
	return true
}

// ---- first-run setup ----

func (s *Server) setupDone(r *http.Request) (bool, error) {
	n, err := s.st.CountUsers(r.Context())
	return n > 0, err
}

func (s *Server) handleSetupForm(w http.ResponseWriter, r *http.Request) {
	done, err := s.setupDone(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if done {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "setup", "First-run setup", "", nil, "")
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	done, err := s.setupDone(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if done {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	username := strings.TrimSpace(r.PostFormValue("username"))
	pw, pw2 := r.PostFormValue("password"), r.PostFormValue("password2")
	errMsg := ""
	switch {
	case !usernameOK(username):
		errMsg = "Username: 1–64 characters, letters, digits and - _ . @ only."
	case pw != pw2:
		errMsg = "The passwords don't match."
	default:
		if err := auth.ValidatePassword(pw); err != nil {
			errMsg = "Password: " + err.Error() + "."
		}
	}
	if errMsg != "" {
		s.render(w, r, http.StatusBadRequest, "setup", "First-run setup", "", map[string]string{"Username": username}, errMsg)
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := s.st.CreateFirstUser(r.Context(), username, hash)
	if err != nil {
		// Lost a race with another setup request.
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.svc.Audit(r.Context(), s.actorNamed(r, username), "setup", 0, "admin account created")
	if err := s.startSession(r, id, hash); err != nil {
		s.fail(w, r, err)
		return
	}
	s.flash(r, "Admin account created. Next: create a root CA.")
	http.Redirect(w, r, "/cas/new", http.StatusSeeOther)
}

// ---- login / logout ----

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	done, err := s.setupDone(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !done {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if s.sessions.GetInt64(r.Context(), sessUID) != 0 {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, r, http.StatusOK, "login", "Sign in", "", nil, "")
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now()
	username := strings.TrimSpace(r.PostFormValue("username"))
	pw := r.PostFormValue("password")
	code := r.PostFormValue("code")
	keys := []string{"ip:" + ipOf(r), "user:" + strings.ToLower(username)}

	if ok, wait := s.limiter.Allowed(now, keys...); !ok {
		s.svc.Audit(ctx, s.actorNamed(r, username), "login-blocked", 0, "rate limited")
		s.render(w, r, http.StatusTooManyRequests, "login", "Sign in", "", map[string]string{"Username": username},
			fmt.Sprintf("Too many failed attempts. Try again in %d minutes.", int(wait.Minutes())+1))
		return
	}
	u, err := s.st.UserByName(ctx, username)
	valid := false
	if err == nil {
		valid, _ = auth.VerifyPassword(u.PasswordHash, pw)
		if valid && u.TOTPSecret != nil {
			secret, err := s.env.Open(u.TOTPSecret, totpAAD(u.ID))
			valid = err == nil && s.totp.Verify(u.ID, string(secret), code, now)
		}
	} else {
		auth.BurnTime(pw) // same timing for unknown users
	}
	if !valid {
		s.limiter.Fail(now, keys...)
		s.svc.Audit(ctx, s.actorNamed(r, username), "login-failed", 0, "")
		s.render(w, r, http.StatusUnauthorized, "login", "Sign in", "", map[string]string{"Username": username},
			"Wrong username, password or authenticator code.")
		return
	}
	s.limiter.Succeed(keys...)
	if err := s.startSession(r, u.ID, u.PasswordHash); err != nil {
		s.fail(w, r, err)
		return
	}
	s.svc.Audit(ctx, s.actorNamed(r, u.Username), "login", 0, "")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// startSession issues a fresh session token (no fixation) and a fresh CSRF token.
func (s *Server) startSession(r *http.Request, uid int64, pwHash string) error {
	ctx := r.Context()
	if err := s.sessions.RenewToken(ctx); err != nil {
		return err
	}
	s.sessions.Remove(ctx, sessCSRF)
	s.sessions.Remove(ctx, sessTOTP)
	s.sessions.Put(ctx, sessUID, uid)
	s.sessions.Put(ctx, sessPWV, pwVersion(pwHash))
	return nil
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.svc.Audit(r.Context(), s.actor(r), "logout", 0, "")
	if err := s.sessions.Destroy(r.Context()); err != nil {
		s.fail(w, r, err)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) actorNamed(r *http.Request, name string) ca.Actor {
	return ca.Actor{Name: name, IP: ipOf(r)}
}

// ---- settings ----

type settingsData struct {
	TOTPEnabled bool
	TOTPPending bool
	TOTPSecret  string
	TOTPQR      template.URL
}

func totpAAD(uid int64) string { return fmt.Sprintf("totp:%d", uid) }

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	u := userOf(r)
	d := settingsData{TOTPEnabled: u.TOTPSecret != nil}
	if sealed := s.sessions.GetBytes(r.Context(), sessTOTP); sealed != nil && !d.TOTPEnabled {
		if url, err := s.env.Open(sealed, totpAAD(u.ID)); err == nil {
			if key, err := otp.NewKeyFromURL(string(url)); err == nil {
				d.TOTPPending, d.TOTPSecret = true, key.Secret()
				if img, err := key.Image(220, 220); err == nil {
					var buf bytes.Buffer
					if png.Encode(&buf, img) == nil {
						// Safe: we generated this PNG ourselves; no user input.
						d.TOTPQR = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())) // #nosec G203
					}
				}
			}
		}
	}
	s.render(w, r, status, "settings", "Settings", "settings", d, errMsg)
}

func (s *Server) handleSettings(w http.ResponseWriter, r *http.Request) {
	s.settingsPage(w, r, http.StatusOK, "")
}

// reauth checks the current password (and slows guessing via the limiter).
func (s *Server) reauth(r *http.Request) bool {
	u := userOf(r)
	now := time.Now()
	key := "reauth:" + ipOf(r)
	if ok, _ := s.limiter.Allowed(now, key); !ok {
		return false
	}
	ok, _ := auth.VerifyPassword(u.PasswordHash, r.PostFormValue("current_password"))
	if !ok {
		s.limiter.Fail(now, key)
	}
	return ok
}

func (s *Server) handlePassword(w http.ResponseWriter, r *http.Request) {
	if !s.reauth(r) {
		s.settingsPage(w, r, http.StatusBadRequest, "Current password is wrong.")
		return
	}
	pw, pw2 := r.PostFormValue("password"), r.PostFormValue("password2")
	if pw != pw2 {
		s.settingsPage(w, r, http.StatusBadRequest, "The new passwords don't match.")
		return
	}
	if err := auth.ValidatePassword(pw); err != nil {
		s.settingsPage(w, r, http.StatusBadRequest, "Password: "+err.Error()+".")
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	u := userOf(r)
	if err := s.st.SetPassword(r.Context(), u.ID, hash); err != nil {
		s.fail(w, r, err)
		return
	}
	s.svc.Audit(r.Context(), s.actor(r), "password-change", 0, "")
	// Every other session now fails the password-version check.
	if err := s.startSession(r, u.ID, hash); err != nil {
		s.fail(w, r, err)
		return
	}
	s.flash(r, "Password changed. Other sessions have been signed out.")
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) handleTOTPStart(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	if u.TOTPSecret != nil {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	key, err := auth.NewTOTP(u.Username)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sealed, err := s.env.Seal([]byte(key.URL()), totpAAD(u.ID))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.sessions.Put(r.Context(), sessTOTP, sealed)
	http.Redirect(w, r, "/settings#totp", http.StatusSeeOther)
}

func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	sealed := s.sessions.GetBytes(r.Context(), sessTOTP)
	if sealed == nil {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	url, err := s.env.Open(sealed, totpAAD(u.ID))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	key, err := otp.NewKeyFromURL(string(url))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.totp.Verify(u.ID, key.Secret(), r.PostFormValue("code"), time.Now()) {
		s.settingsPage(w, r, http.StatusBadRequest, "That code didn't match. Check your device's clock and try again.")
		return
	}
	stored, err := s.env.Seal([]byte(key.Secret()), totpAAD(u.ID))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.st.SetTOTP(r.Context(), u.ID, stored); err != nil {
		s.fail(w, r, err)
		return
	}
	s.sessions.Remove(r.Context(), sessTOTP)
	s.svc.Audit(r.Context(), s.actor(r), "totp-enable", 0, "")
	s.flash(r, "Two-factor authentication is on.")
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	if !s.reauth(r) {
		s.settingsPage(w, r, http.StatusBadRequest, "Current password is wrong.")
		return
	}
	if err := s.st.SetTOTP(r.Context(), userOf(r).ID, nil); err != nil {
		s.fail(w, r, err)
		return
	}
	s.svc.Audit(r.Context(), s.actor(r), "totp-disable", 0, "")
	s.flash(r, "Two-factor authentication is off.")
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	if !s.reauth(r) {
		s.settingsPage(w, r, http.StatusBadRequest, "Current password is wrong.")
		return
	}
	pass := r.PostFormValue("passphrase")
	if pass != "" && len(pass) < auth.MinPasswordLength {
		s.settingsPage(w, r, http.StatusBadRequest, fmt.Sprintf("Backup passphrase must be at least %d characters (or empty for no encryption).", auth.MinPasswordLength))
		return
	}
	name := backup.FileName(time.Now(), pass != "")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	m, err := backup.Write(r.Context(), s.st, w, pass, s.cfg.Version, s.cfg.DataDir)
	if err != nil {
		// Headers may be sent already; the download will be truncated.
		s.log.Error("backup download failed", "err", err)
		return
	}
	s.svc.Audit(r.Context(), s.actor(r), "backup", 0, fmt.Sprintf("download encrypted=%t size=%d", pass != "", m.DBSize))
}
