// Entry point: read config, connect to postgres, run the shell.
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"cli-login/internal/auth"
	"cli-login/internal/cli"
	"cli-login/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = store.DSN(
			env("DB_HOST", "db"),
			env("DB_PORT", "5432"),
			env("DB_USER", "cliauth"),
			env("DB_PASSWORD", "cliauth"),
			env("DB_NAME", "cliauth"),
			env("DB_SSLMODE", "disable"),
		)
	}

	fmt.Println("Connecting to the database…")
	db, err := store.Open(ctx, dsn, envDuration("DB_CONNECT_TIMEOUT", 30*time.Second))
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.Migrate(ctx); err != nil {
		return err
	}
	if err := db.DeleteExpiredSessions(ctx); err != nil {
		return err
	}

	service, err := auth.New(db, auth.Config{
		SessionTimeout:  envDuration("SESSION_TIMEOUT", 15*time.Minute),
		MaxAttempts:     envInt("MAX_FAILED_ATTEMPTS", 5),
		LockoutDuration: envDuration("LOCKOUT_DURATION", 5*time.Minute),
		BcryptCost:      envInt("BCRYPT_COST", 12),
		Issuer:          env("TOTP_ISSUER", "cli-login"),
	})
	if err != nil {
		return err
	}

	shell, err := cli.New(service)
	if err != nil {
		return err
	}
	defer shell.Close()

	fmt.Printf("\ncli-login — session timeout %s, lockout after %d failed attempts.\n",
		service.Config().SessionTimeout, service.Config().MaxAttempts)
	return shell.Run(ctx)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Fall back to the default on junk input, so a typo can't disable a security setting.
func envDuration(key string, fallback time.Duration) time.Duration {
	if v, err := time.ParseDuration(env(key, "")); err == nil && v > 0 {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v, err := strconv.Atoi(env(key, "")); err == nil && v > 0 {
		return v
	}
	return fallback
}
