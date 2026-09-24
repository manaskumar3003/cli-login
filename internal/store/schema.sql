-- Applied at startup by store.Migrate.

CREATE TABLE IF NOT EXISTS users (
    id              BIGSERIAL PRIMARY KEY,
    username        TEXT        NOT NULL UNIQUE,
    password_hash   TEXT        NOT NULL,
    totp_secret     TEXT,                 -- null = 2FA off
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at   TIMESTAMPTZ,
    failed_attempts INT         NOT NULL DEFAULT 0,
    locked_until    TIMESTAMPTZ           -- null = not locked
);

CREATE TABLE IF NOT EXISTS sessions (
    token      TEXT        PRIMARY KEY,
    user_id    BIGINT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_expires_at_idx ON sessions (expires_at);
