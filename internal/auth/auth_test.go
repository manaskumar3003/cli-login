package auth_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"cli-login/internal/auth"
	"cli-login/internal/store"
)

func TestValidateUsername(t *testing.T) {
	ok, err := auth.ValidateUsername("  Alice_01 ")
	if err != nil || ok != "alice_01" {
		t.Fatalf("got %q, %v; want %q, nil", ok, err, "alice_01")
	}
	for _, bad := range []string{"ab", "has space", "no!", strings.Repeat("a", 33)} {
		if _, err := auth.ValidateUsername(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestValidatePassword(t *testing.T) {
	if err := auth.ValidatePassword("correct horse"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, bad := range []string{"short", strings.Repeat("x", 73)} {
		if err := auth.ValidatePassword(bad); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

// Needs DATABASE_URL; without it the db-backed tests skip.
func newService(t *testing.T, cfg auth.Config) (*auth.Service, context.Context) {
	t.Helper()
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping database-backed test")
	}
	ctx := context.Background()
	db, err := store.Open(ctx, dsn, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if cfg.BcryptCost == 0 {
		cfg.BcryptCost = 4 // minimum cost: these tests hash a lot
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "test"
	}
	svc, err := auth.New(db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return svc, ctx
}

func noTOTP() (string, error) { return "", errors.New("2FA should not have been requested") }

// The db persists between runs, so every test needs its own user.
func uniqueName(t *testing.T) string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "u" + hex.EncodeToString(b)
}

func TestLoginAndSession(t *testing.T) {
	svc, ctx := newService(t, auth.Config{SessionTimeout: time.Minute, MaxAttempts: 5, LockoutDuration: time.Minute})
	name := uniqueName(t)
	if _, err := svc.Register(ctx, name, "hunter2hunter2"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Register(ctx, name, "hunter2hunter2"); !errors.Is(err, auth.ErrUserExists) {
		t.Fatalf("duplicate registration: got %v, want ErrUserExists", err)
	}
	if _, err := svc.Login(ctx, name, "wrong-password", noTOTP); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("wrong password: got %v, want ErrInvalidCredentials", err)
	}
	session, err := svc.Login(ctx, name, "hunter2hunter2", noTOTP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Refresh(ctx, session.Token); err != nil {
		t.Fatalf("refresh a live session: %v", err)
	}
	if err := svc.Logout(ctx, session.Token); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Refresh(ctx, session.Token); !errors.Is(err, auth.ErrSessionExpired) {
		t.Fatalf("after logout: got %v, want ErrSessionExpired", err)
	}
}

func TestSessionTimeout(t *testing.T) {
	svc, ctx := newService(t, auth.Config{SessionTimeout: time.Second, MaxAttempts: 5, LockoutDuration: time.Minute})
	name := uniqueName(t)
	if _, err := svc.Register(ctx, name, "hunter2hunter2"); err != nil {
		t.Fatal(err)
	}
	session, err := svc.Login(ctx, name, "hunter2hunter2", noTOTP)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond)
	if _, err := svc.Refresh(ctx, session.Token); !errors.Is(err, auth.ErrSessionExpired) {
		t.Fatalf("expired session: got %v, want ErrSessionExpired", err)
	}
}

func TestLockoutAfterFailedAttempts(t *testing.T) {
	const maxAttempts = 3
	svc, ctx := newService(t, auth.Config{SessionTimeout: time.Minute, MaxAttempts: maxAttempts, LockoutDuration: time.Minute})
	name := uniqueName(t)
	if _, err := svc.Register(ctx, name, "hunter2hunter2"); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= maxAttempts; i++ {
		_, err := svc.Login(ctx, name, "nope", noTOTP)
		var locked *auth.LockedError
		switch {
		case i < maxAttempts && !errors.Is(err, auth.ErrInvalidCredentials):
			t.Fatalf("attempt %d: got %v, want ErrInvalidCredentials", i, err)
		case i == maxAttempts && !errors.As(err, &locked):
			t.Fatalf("attempt %d: got %v, want LockedError", i, err)
		}
	}
	// Correct password must still fail while locked.
	if _, err := svc.Login(ctx, name, "hunter2hunter2", noTOTP); err == nil {
		t.Fatal("locked account accepted the correct password")
	}
}

func TestTwoFactorFlow(t *testing.T) {
	svc, ctx := newService(t, auth.Config{SessionTimeout: time.Minute, MaxAttempts: 5, LockoutDuration: time.Minute})
	name := uniqueName(t)
	user, err := svc.Register(ctx, name, "hunter2hunter2")
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := svc.Begin2FA(user)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Confirm2FA(ctx, user, enrollment, "000000"); !errors.Is(err, auth.ErrInvalidTOTP) {
		t.Fatalf("wrong confirmation code: got %v, want ErrInvalidTOTP", err)
	}
	code := func() string {
		c, err := totp.GenerateCode(enrollment.Secret, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	if err := svc.Confirm2FA(ctx, user, enrollment, code()); err != nil {
		t.Fatal(err)
	}
	// Login must now ask for a code.
	if _, err := svc.Login(ctx, name, "hunter2hunter2", func() (string, error) { return "000000", nil }); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("bad 2FA code: got %v, want a rejected login", err)
	}
	session, err := svc.Login(ctx, name, "hunter2hunter2", func() (string, error) { return code(), nil })
	if err != nil {
		t.Fatal(err)
	}
	if !session.User.TwoFactorEnabled() {
		t.Fatal("session user should report 2FA as enabled")
	}
	if err := svc.Disable2FA(ctx, session.User, code()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Login(ctx, name, "hunter2hunter2", noTOTP); err != nil {
		t.Fatalf("login after disabling 2FA: %v", err)
	}
}
