// Package auth holds the security rules: hashing, lockout, TOTP, sessions.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"

	"cli-login/internal/store"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrInvalidTOTP        = errors.New("invalid 2FA code")
	ErrUserExists         = store.ErrDuplicateUser
	Err2FAEnabled         = errors.New("2FA is already enabled")
	Err2FADisabled        = errors.New("2FA is not enabled")
	ErrSessionExpired     = errors.New("session expired, please log in again")
)

type LockedError struct{ Until time.Time }

func (e *LockedError) Error() string {
	return fmt.Sprintf("account locked, try again in %s", time.Until(e.Until).Round(time.Second))
}

type Config struct {
	SessionTimeout  time.Duration // how long a session stays valid without activity
	MaxAttempts     int           // failed logins before the account locks
	LockoutDuration time.Duration // how long the lock lasts
	BcryptCost      int
	Issuer          string // shown in the authenticator app
}

type Service struct {
	store *store.Store
	cfg   Config
	// Hashed at the configured cost so an unknown user takes as long as a known one.
	absentUserHash []byte
}

func New(s *store.Store, cfg Config) (*Service, error) {
	if cfg.BcryptCost < bcrypt.MinCost || cfg.BcryptCost > bcrypt.MaxCost {
		return nil, fmt.Errorf("bcrypt cost must be between %d and %d, got %d",
			bcrypt.MinCost, bcrypt.MaxCost, cfg.BcryptCost)
	}
	absent, err := bcrypt.GenerateFromPassword([]byte("no such user"), cfg.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("initialise password hashing: %w", err)
	}
	return &Service{store: s, cfg: cfg, absentUserHash: absent}, nil
}

func (s *Service) Config() Config { return s.cfg }

type Session struct {
	Token     string
	User      *store.User
	ExpiresAt time.Time
	// Login before this one; zero on a first login.
	PreviousLogin time.Time
}

var usernameRE = regexp.MustCompile(`^[a-z0-9_.-]{3,32}$`)

func ValidateUsername(username string) (string, error) {
	u := strings.ToLower(strings.TrimSpace(username))
	if !usernameRE.MatchString(u) {
		return "", errors.New("username must be 3-32 characters of letters, digits, '.', '-' or '_'")
	}
	return u, nil
}

// bcrypt truncates at 72 bytes, so reject longer instead of silently trimming.
func ValidatePassword(password string) error {
	switch {
	case len(password) < 8:
		return errors.New("password must be at least 8 characters")
	case len(password) > 72:
		return errors.New("password must be at most 72 bytes")
	}
	return nil
}

func (s *Service) Register(ctx context.Context, username, password string) (*store.User, error) {
	name, err := ValidateUsername(username)
	if err != nil {
		return nil, err
	}
	if err := ValidatePassword(password); err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cfg.BcryptCost)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}
	return s.store.CreateUser(ctx, name, string(hash))
}

// Only called when the account has 2FA on.
type TOTPPrompt func() (string, error)

func (s *Service) Login(ctx context.Context, username, password string, promptTOTP TOTPPrompt) (*Session, error) {
	name, err := ValidateUsername(username)
	if err != nil {
		return nil, ErrInvalidCredentials
	}
	user, err := s.store.UserByUsername(ctx, name)
	if errors.Is(err, store.ErrNotFound) {
		bcrypt.CompareHashAndPassword(s.absentUserHash, []byte(password))
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, err
	}
	if user.Locked(time.Now()) {
		return nil, &LockedError{Until: user.LockedUntil}
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		return nil, s.fail(ctx, user)
	}
	if user.TwoFactorEnabled() {
		code, err := promptTOTP()
		if err != nil {
			return nil, err
		}
		if !totp.Validate(strings.TrimSpace(code), user.TOTPSecret) {
			return nil, s.fail(ctx, user)
		}
	}
	previousLogin := user.LastLoginAt
	if err := s.store.RecordSuccess(ctx, user.ID); err != nil {
		return nil, err
	}
	// Reload for the cleared counters.
	if user, err = s.store.UserByID(ctx, user.ID); err != nil {
		return nil, err
	}
	session, err := s.startSession(ctx, user)
	if err != nil {
		return nil, err
	}
	session.PreviousLogin = previousLogin
	return session, nil
}

func (s *Service) fail(ctx context.Context, user *store.User) error {
	_, lockedUntil, err := s.store.RecordFailure(ctx, user.ID, s.cfg.MaxAttempts, s.cfg.LockoutDuration)
	if err != nil {
		return err
	}
	if time.Now().Before(lockedUntil) {
		return &LockedError{Until: lockedUntil}
	}
	return ErrInvalidCredentials
}

func (s *Service) startSession(ctx context.Context, user *store.User) (*Session, error) {
	token, err := newToken()
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(s.cfg.SessionTimeout)
	if err := s.store.CreateSession(ctx, token, user.ID, expiresAt); err != nil {
		return nil, err
	}
	return &Session{Token: token, User: user, ExpiresAt: expiresAt}, nil
}

// Slides the expiry forward, so an active user isn't logged out mid-work.
func (s *Service) Refresh(ctx context.Context, token string) (*Session, error) {
	user, _, err := s.store.SessionUser(ctx, token)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrSessionExpired
	}
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(s.cfg.SessionTimeout)
	if err := s.store.ExtendSession(ctx, token, expiresAt); err != nil {
		return nil, err
	}
	return &Session{Token: token, User: user, ExpiresAt: expiresAt}, nil
}

func (s *Service) Logout(ctx context.Context, token string) error {
	return s.store.DeleteSession(ctx, token)
}

// An unconfirmed 2FA secret.
type Enrollment struct {
	Secret string // base32 secret, for manual entry
	URL    string // otpauth:// URL, for the QR code
}

// Not saved until Confirm2FA proves the app produces matching codes.
func (s *Service) Begin2FA(user *store.User) (*Enrollment, error) {
	if user.TwoFactorEnabled() {
		return nil, Err2FAEnabled
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: s.cfg.Issuer, AccountName: user.Username})
	if err != nil {
		return nil, fmt.Errorf("generate 2FA secret: %w", err)
	}
	return &Enrollment{Secret: key.Secret(), URL: key.URL()}, nil
}

func (s *Service) Confirm2FA(ctx context.Context, user *store.User, e *Enrollment, code string) error {
	if !totp.Validate(strings.TrimSpace(code), e.Secret) {
		return ErrInvalidTOTP
	}
	if err := s.store.SetTOTPSecret(ctx, user.ID, e.Secret); err != nil {
		return err
	}
	user.TOTPSecret = e.Secret
	return nil
}

// Needs a current code, so only someone holding the device can turn it off.
func (s *Service) Disable2FA(ctx context.Context, user *store.User, code string) error {
	if !user.TwoFactorEnabled() {
		return Err2FADisabled
	}
	if !totp.Validate(strings.TrimSpace(code), user.TOTPSecret) {
		return ErrInvalidTOTP
	}
	if err := s.store.SetTOTPSecret(ctx, user.ID, ""); err != nil {
		return err
	}
	user.TOTPSecret = ""
	return nil
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
