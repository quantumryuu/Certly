// Package auth handles password hashing (argon2id), TOTP and login rate limiting.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"
)

// Password rules.
const (
	MinPasswordLength = 12
	MaxPasswordLength = 256
)

// argon2id parameters (above OWASP minimums).
const (
	argonMemory  = 64 * 1024 // KiB
	argonTime    = 3
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
	// Bounds when parsing stored hashes, so a tampered row can't make us
	// allocate gigabytes.
	maxArgonMemory = 1024 * 1024
	maxArgonTime   = 20
)

// ValidatePassword checks a new password against the rules.
func ValidatePassword(pw string) error {
	n := utf8.RuneCountInString(pw)
	if n < MinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	}
	if len(pw) > MaxPasswordLength {
		return fmt.Errorf("password must be at most %d bytes", MaxPasswordLength)
	}
	return nil
}

// HashPassword returns a PHC-format argon2id hash.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: salt: %w", err)
	}
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

var errBadHash = errors.New("auth: malformed password hash")

// VerifyPassword checks pw against an encoded hash in constant time.
func VerifyPassword(encoded, pw string) (bool, error) {
	if len(pw) > MaxPasswordLength {
		return false, nil
	}
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errBadHash
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, errBadHash
	}
	if m == 0 || m > maxArgonMemory || t == 0 || t > maxArgonTime || p == 0 {
		return false, errBadHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, errBadHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) < 16 || len(want) > 64 {
		return false, errBadHash
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want))) // #nosec G115 -- len bounded above
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

var (
	dummyOnce sync.Once
	dummyHash string
)

// BurnTime runs a hash verification against a dummy hash, so a login for an
// unknown user takes as long as one for a real user.
func BurnTime(pw string) {
	dummyOnce.Do(func() { dummyHash, _ = HashPassword("dummy-password-for-timing") })
	_, _ = VerifyPassword(dummyHash, pw)
}

// ---- TOTP ----

// NewTOTP generates a TOTP key for enrolment.
func NewTOTP(account string) (*otp.Key, error) {
	k, err := totp.Generate(totp.GenerateOpts{Issuer: "Certly", AccountName: account, Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		return nil, fmt.Errorf("auth: generate TOTP: %w", err)
	}
	return k, nil
}

// TOTPVerifier checks codes and rejects replays of a code already used.
type TOTPVerifier struct {
	mu       sync.Mutex
	lastStep map[int64]uint64
}

// NewTOTPVerifier creates a verifier.
func NewTOTPVerifier() *TOTPVerifier { return &TOTPVerifier{lastStep: map[int64]uint64{}} }

// Verify checks a 6-digit code for user id at time now (±1 step of skew).
// A code (time step) can be used only once per user.
func (v *TOTPVerifier) Verify(userID int64, secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	cur := uint64(now.Unix()) / 30 // #nosec G115 -- current time is positive
	for _, step := range []uint64{cur - 1, cur, cur + 1} {
		if step <= v.lastStep[userID] {
			continue
		}
		at := time.Unix(int64(step*30), 0) // #nosec G115 -- small value
		ok, err := totp.ValidateCustom(code, secret, at, totp.ValidateOpts{Period: 30, Skew: 0, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
		if err == nil && ok {
			v.lastStep[userID] = step
			return true
		}
	}
	return false
}

// ---- rate limiting ----

// Limiter locks out a key (IP or username) after too many failed logins.
type Limiter struct {
	mu       sync.Mutex
	entries  map[string]*limitEntry
	MaxFails int
	Window   time.Duration
	Lockout  time.Duration
}

type limitEntry struct {
	fails       int
	first       time.Time
	lockedUntil time.Time
}

const maxLimiterEntries = 10000

// NewLimiter allows 5 failures per 15 minutes, then locks for 15 minutes.
func NewLimiter() *Limiter {
	return &Limiter{entries: map[string]*limitEntry{}, MaxFails: 5, Window: 15 * time.Minute, Lockout: 15 * time.Minute}
}

// Allowed reports whether attempts for all keys are allowed, and if not, how
// long until they are.
func (l *Limiter) Allowed(now time.Time, keys ...string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		if e, ok := l.entries[k]; ok && now.Before(e.lockedUntil) {
			return false, e.lockedUntil.Sub(now)
		}
	}
	return true, 0
}

// Fail records a failure for each key.
func (l *Limiter) Fail(now time.Time, keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) > maxLimiterEntries {
		l.prune(now)
	}
	for _, k := range keys {
		e, ok := l.entries[k]
		if !ok || now.Sub(e.first) > l.Window {
			e = &limitEntry{first: now}
			l.entries[k] = e
		}
		e.fails++
		if e.fails >= l.MaxFails {
			e.lockedUntil = now.Add(l.Lockout)
			e.fails = 0
			e.first = now
		}
	}
}

// Succeed clears the failures for the keys.
func (l *Limiter) Succeed(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.entries, k)
	}
}

func (l *Limiter) prune(now time.Time) {
	for k, e := range l.entries {
		if now.After(e.lockedUntil) && now.Sub(e.first) > l.Window {
			delete(l.entries, k)
		}
	}
	// Still full (e.g. a flood of distinct IPs): drop everything not locked.
	if len(l.entries) > maxLimiterEntries {
		for k, e := range l.entries {
			if now.After(e.lockedUntil) {
				delete(l.entries, k)
			}
		}
	}
}
