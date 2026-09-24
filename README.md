# cli-login

Interactive CLI login system in Go: registration, password login, optional TOTP
2FA, account lockout and expiring sessions. App and PostgreSQL both run in Docker.

## Run

```sh
docker compose run --rm app
```

Builds the image, starts Postgres, applies the schema. `run` rather than `up`
because the CLI needs a terminal. Data lives in the `pgdata` volume and survives
restarts.

```sh
docker compose down      # keep data
docker compose down -v   # drop it
```

## Commands

Before login: `register`, `login`, `help`, `exit`.
After login: `whoami`, `enable-2fa`, `disable-2fa`, `logout`, `help`, `exit`.

`register` and `login` take an optional username (`login alice`) or prompt for
it. Tab completes the commands valid in the current state, ↑/↓ walks history,
Ctrl-R searches it, Ctrl-D quits.

`enable-2fa` prints a QR code for Google Authenticator plus the secret for
manual entry. The secret is only stored after you type a code it generated, so
a bad scan can't lock you out. Turning 2FA off needs a current code.

Login prints username, registration date, MFA status, session expiry and
previous login; `whoami` reprints it.

## Config

Environment variables, read from `.env` (see `.env.example`):

| Variable | Default | |
|---|---|---|
| `SESSION_TIMEOUT` | `15m` | inactivity before a session expires |
| `MAX_FAILED_ATTEMPTS` | `5` | failed logins before lockout |
| `LOCKOUT_DURATION` | `5m` | how long the lock lasts |
| `BCRYPT_COST` | `12` | password hashing work factor |
| `TOTP_ISSUER` | `cli-login` | name in the authenticator app |
| `DB_HOST` `DB_PORT` `DB_USER` `DB_PASSWORD` `DB_NAME` | `db` `5432` `cliauth` ×3 | database |
| `DATABASE_URL` | — | full connection string, overrides `DB_*` |

The defaults make a fresh clone run. Anywhere real, set a proper `DB_PASSWORD`
and `DB_SSLMODE=require`. Compose exposes no ports; the database is only
reachable from the app container.

## Security

- bcrypt (cost 12); passwords over bcrypt's 72-byte limit are rejected, not truncated.
- Lockout applied in one SQL `UPDATE`, so parallel attempts can't race past the limit. A locked account is refused even with the right password, and a wrong TOTP code counts as a failure.
- Unknown usernames still cost a bcrypt compare, so they can't be found by timing. The error is always "invalid username or password".
- Sessions are 256-bit `crypto/rand` tokens stored server-side with an expiry, re-checked on every command and deleted on logout.

## Layout

```
cmd/cli/main.go    config, wiring, startup
internal/store/    postgres access + schema.sql (embedded, idempotent)
internal/auth/     hashing, lockout, TOTP, sessions
internal/cli/      the shell
```

`cli` never touches SQL, `auth` never touches the terminal.

Tables: **users** (`id`, `username` unique, `password_hash`, `totp_secret` null
when off, `created_at`, `last_login_at`, `failed_attempts`, `locked_until`) and
**sessions** (`token`, `user_id` → users on delete cascade, `created_at`,
`expires_at`).

## Tests

```sh
docker compose run --rm test
```

Registration and duplicates, wrong passwords, lockout, session expiry and
logout, and the full 2FA enable → login → disable cycle, against a real Postgres.
