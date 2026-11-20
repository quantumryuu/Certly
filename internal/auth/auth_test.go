package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestPasswordHash(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("hash %s", h)
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("same salt twice")
	}
	tests := []struct {
		pw   string
		want bool
	}{{"correct horse battery", true}, {"correct horse batterY", false}, {"", false}, {strings.Repeat("a", 300), false}}
	for _, tc := range tests {
		if ok, err := VerifyPassword(h, tc.pw); ok != tc.want || err != nil {
			t.Fatalf("verify %q = %v, %v", tc.pw, ok, err)
		}
	}
}

func TestVerifyRejectsMalformedAndExpensive(t *testing.T) {
	for _, h := range []string{
		"", "plaintext", "$argon2i$v=19$m=65536,t=3,p=2$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=99999999,t=3,p=2$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=65536,t=999,p=2$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA",
	} {
		if ok, err := VerifyPassword(h, "x"); ok || err == nil {
			t.Fatalf("accepted %q", h)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	if ValidatePassword("short") == nil || ValidatePassword(strings.Repeat("x", 257)) == nil {
		t.Fatal("bad password accepted")
	}
	if err := ValidatePassword("twelve chars"); err != nil {
		t.Fatal(err)
	}
}

func TestTOTPReplay(t *testing.T) {
	k, err := NewTOTP("admin")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	code, _ := totp.GenerateCode(k.Secret(), now)
	v := NewTOTPVerifier()
	if !v.Verify(1, k.Secret(), code, now) {
		t.Fatal("valid code rejected")
	}
	if v.Verify(1, k.Secret(), code, now) {
		t.Fatal("replayed code accepted")
	}
	if v.Verify(2, k.Secret(), "000000", now) && code != "000000" {
		t.Fatal("wrong code accepted")
	}
	old, _ := totp.GenerateCode(k.Secret(), now.Add(-5*time.Minute))
	if v.Verify(3, k.Secret(), old, now) {
		t.Fatal("stale code accepted")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter()
	now := time.Now()
	for i := 0; i < 4; i++ {
		l.Fail(now, "ip:1")
	}
	if ok, _ := l.Allowed(now, "ip:1"); !ok {
		t.Fatal("locked too early")
	}
	l.Fail(now, "ip:1")
	if ok, wait := l.Allowed(now, "ip:1", "user:x"); ok || wait <= 0 {
		t.Fatal("not locked after 5 failures")
	}
	if ok, _ := l.Allowed(now.Add(16*time.Minute), "ip:1"); !ok {
		t.Fatal("lock did not expire")
	}
	l.Succeed("ip:1")
	if ok, _ := l.Allowed(now, "ip:1"); !ok {
		t.Fatal("success did not clear")
	}
}
