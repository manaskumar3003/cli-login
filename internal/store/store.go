// Package store is the only package that talks to postgres.
package store

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

//go:embed schema.sql
var schema string

var ErrNotFound = errors.New("not found")

var ErrDuplicateUser = errors.New("username already taken")

type Store struct{ db *sql.DB }

type User struct {
	ID             int64
	Username       string
	PasswordHash   string
	TOTPSecret     string // "" means 2FA is disabled
	CreatedAt      time.Time
	LastLoginAt    time.Time // zero value means "never"
	FailedAttempts int
	LockedUntil    time.Time // zero value means "not locked"
}

func (u *User) TwoFactorEnabled() bool { return u.TOTPSecret != "" }

func (u *User) Locked(now time.Time) bool { return now.Before(u.LockedUntil) }

// Open retries until postgres accepts connections; the db container starts after us.
func Open(ctx context.Context, dsn string, waitFor time.Duration) (*Store, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	deadline := time.Now().Add(waitFor)
	for {
		if err = db.PingContext(ctx); err == nil {
			return &Store{db: db}, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			db.Close()
			return nil, fmt.Errorf("database unreachable after %s: %w", waitFor, err)
		}
		select {
		case <-ctx.Done():
			db.Close()
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (s *Store) Close() error { return s.db.Close() }

// Idempotent, so it runs on every start.
func (s *Store) Migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}
	return nil
}

const userColumns = `id, username, password_hash, totp_secret, created_at,
	last_login_at, failed_attempts, locked_until`

// Nullable columns come back as zero values.
func scanUser(row *sql.Row) (*User, error) {
	var (
		u           User
		totpSecret  sql.NullString
		lastLogin   sql.NullTime
		lockedUntil sql.NullTime
	)
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &totpSecret, &u.CreatedAt,
		&lastLogin, &u.FailedAttempts, &lockedUntil)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil, ErrNotFound
	case err != nil:
		return nil, err
	}
	u.TOTPSecret = totpSecret.String
	u.LastLoginAt = lastLogin.Time
	u.LockedUntil = lockedUntil.Time
	return &u, nil
}

func (s *Store) CreateUser(ctx context.Context, username, passwordHash string) (*User, error) {
	row := s.db.QueryRowContext(ctx,
		`INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING `+userColumns,
		username, passwordHash)
	u, err := scanUser(row)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
			return nil, ErrDuplicateUser
		}
		return nil, fmt.Errorf("create user: %w", err)
	}
	return u, nil
}

func (s *Store) UserByUsername(ctx context.Context, username string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE username = $1`, username))
}

func (s *Store) UserByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx,
		`SELECT `+userColumns+` FROM users WHERE id = $1`, id))
}

// One statement, so parallel attempts can't race past the limit.
func (s *Store) RecordFailure(ctx context.Context, id int64, maxAttempts int, lockFor time.Duration) (attempts int, lockedUntil time.Time, err error) {
	var locked sql.NullTime
	err = s.db.QueryRowContext(ctx, `
		UPDATE users SET
			failed_attempts = failed_attempts + 1,
			locked_until = CASE WHEN failed_attempts + 1 >= $2
				THEN now() + make_interval(secs => $3) ELSE locked_until END
		WHERE id = $1
		RETURNING failed_attempts, locked_until`,
		id, maxAttempts, lockFor.Seconds()).Scan(&attempts, &locked)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("record failed attempt: %w", err)
	}
	return attempts, locked.Time, nil
}

func (s *Store) RecordSuccess(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login_at = now() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("record successful login: %w", err)
	}
	return nil
}

// Empty secret disables 2FA.
func (s *Store) SetTOTPSecret(ctx context.Context, id int64, secret string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET totp_secret = NULLIF($2, '') WHERE id = $1`, id, secret)
	if err != nil {
		return fmt.Errorf("update 2FA secret: %w", err)
	}
	return nil
}

func (s *Store) CreateSession(ctx context.Context, token string, userID int64, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token, user_id, expires_at) VALUES ($1, $2, $3)`, token, userID, expiresAt)
	if err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// Expired rows count as missing.
func (s *Store) SessionUser(ctx context.Context, token string) (*User, time.Time, error) {
	var expiresAt time.Time
	var userID int64
	err := s.db.QueryRowContext(ctx,
		`SELECT user_id, expires_at FROM sessions WHERE token = $1 AND expires_at > now()`,
		token).Scan(&userID, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, ErrNotFound
	}
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("load session: %w", err)
	}
	u, err := s.UserByID(ctx, userID)
	if err != nil {
		return nil, time.Time{}, err
	}
	return u, expiresAt, nil
}

// Sliding timeout: push the expiry out on activity.
func (s *Store) ExtendSession(ctx context.Context, token string, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET expires_at = $2 WHERE token = $1`, token, expiresAt)
	if err != nil {
		return fmt.Errorf("extend session: %w", err)
	}
	return nil
}

func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token = $1`, token)
	if err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func (s *Store) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= now()`)
	return err
}

func DSN(host, port, user, password, dbname, sslmode string) string {
	esc := func(v string) string {
		return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(v) + "'"
	}
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		esc(host), esc(port), esc(user), esc(password), esc(dbname), esc(sslmode))
}
