// Package cli is the interactive shell. No security logic lives here.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/chzyer/readline"
	"github.com/mdp/qrterminal/v3"

	"cli-login/internal/auth"
)

const timeFormat = "2006-01-02 15:04:05 MST"

type command struct {
	help string
	run  func(ctx context.Context, args []string) error
}

type CLI struct {
	auth    *auth.Service
	rl      *readline.Instance
	session *auth.Session // nil when logged out

	loggedOut map[string]command
	loggedIn  map[string]command
	quit      bool
}

func New(a *auth.Service) (*CLI, error) {
	c := &CLI{auth: a}
	c.loggedOut = map[string]command{
		"register": {"create a new user account", c.cmdRegister},
		"login":    {"log in with username and password (+ 2FA code if enabled)", c.cmdLogin},
		"help":     {"show available commands", c.cmdHelp},
		"exit":     {"quit the program", c.cmdExit},
	}
	c.loggedIn = map[string]command{
		"whoami":      {"show details of the current user", c.cmdWhoami},
		"enable-2fa":  {"turn on TOTP two-factor authentication", c.cmdEnable2FA},
		"disable-2fa": {"turn off TOTP two-factor authentication", c.cmdDisable2FA},
		"logout":      {"end the current session", c.cmdLogout},
		"help":        {"show available commands", c.cmdHelp},
		"exit":        {"quit the program", c.cmdExit},
	}

	rl, err := readline.NewEx(&readline.Config{
		Prompt:            promptFor(nil),
		HistoryFile:       historyFile(),
		HistoryLimit:      500,
		AutoComplete:      &completer{cli: c},
		InterruptPrompt:   "^C",
		EOFPrompt:         "exit",
		HistorySearchFold: true,
	})
	if err != nil {
		return nil, fmt.Errorf("start interactive prompt: %w", err)
	}
	c.rl = rl
	return c, nil
}

func (c *CLI) Close() error { return c.rl.Close() }

func (c *CLI) Run(ctx context.Context) error {
	c.printf("Type %s to see available commands.\n\n", bold("help"))
	for !c.quit {
		c.rl.SetPrompt(promptFor(c.session))
		line, err := c.rl.Readline()
		switch {
		case errors.Is(err, readline.ErrInterrupt): // Ctrl-C clears the line
			continue
		case errors.Is(err, io.EOF): // Ctrl-D quits
			c.printf("\n")
			return nil
		case err != nil:
			return err
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if err := c.dispatch(ctx, fields[0], fields[1:]); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			c.fail(err)
		}
	}
	return nil
}

func (c *CLI) dispatch(ctx context.Context, name string, args []string) error {
	cmd, ok := c.commands()[strings.ToLower(name)]
	if !ok {
		// Better than a blank "unknown command".
		if _, wrongState := c.otherCommands()[strings.ToLower(name)]; wrongState {
			if c.session == nil {
				return fmt.Errorf("%q is only available after login", name)
			}
			return fmt.Errorf("%q is only available before login", name)
		}
		return fmt.Errorf("unknown command %q — type 'help' to see what is available", name)
	}
	// Every command while logged in checks and refreshes the session.
	if c.session != nil {
		s, err := c.auth.Refresh(ctx, c.session.Token)
		if errors.Is(err, auth.ErrSessionExpired) {
			c.session = nil
			return err
		} else if err != nil {
			return err
		}
		s.PreviousLogin = c.session.PreviousLogin // Refresh cannot know it
		c.session = s
	}
	return cmd.run(ctx, args)
}

func (c *CLI) commands() map[string]command {
	if c.session == nil {
		return c.loggedOut
	}
	return c.loggedIn
}

func (c *CLI) otherCommands() map[string]command {
	if c.session == nil {
		return c.loggedIn
	}
	return c.loggedOut
}

// --- commands ---

func (c *CLI) cmdHelp(context.Context, []string) error {
	state := "before login"
	if c.session != nil {
		state = "logged in as " + c.session.User.Username
	}
	c.printf("\nCommands (%s):\n", state)
	cmds := c.commands()
	names := make([]string, 0, len(cmds))
	for n := range cmds {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		c.printf("  %-12s %s\n", bold(n), cmds[n].help)
	}
	c.printf("\nUse Tab to complete commands and ↑/↓ to browse history.\n\n")
	return nil
}

func (c *CLI) cmdExit(ctx context.Context, _ []string) error {
	if c.session != nil {
		// Don't leave a usable session behind.
		if err := c.auth.Logout(ctx, c.session.Token); err != nil {
			return err
		}
		c.session = nil
	}
	c.quit = true
	c.printf("Bye.\n")
	return nil
}

func (c *CLI) cmdRegister(ctx context.Context, args []string) error {
	username, err := c.askUsername(args)
	if err != nil {
		return err
	}
	password, err := c.rl.ReadPassword("Password: ")
	if err != nil {
		return err
	}
	confirm, err := c.rl.ReadPassword("Confirm password: ")
	if err != nil {
		return err
	}
	if string(password) != string(confirm) {
		return errors.New("passwords do not match")
	}
	user, err := c.auth.Register(ctx, username, string(password))
	if err != nil {
		return err
	}
	c.ok("user %s registered. Use 'login' to sign in.", bold(user.Username))
	return nil
}

func (c *CLI) cmdLogin(ctx context.Context, args []string) error {
	username, err := c.askUsername(args)
	if err != nil {
		return err
	}
	password, err := c.rl.ReadPassword("Password: ")
	if err != nil {
		return err
	}
	session, err := c.auth.Login(ctx, username, string(password), func() (string, error) {
		return c.ask("2FA code: ")
	})
	if err != nil {
		return err
	}
	c.session = session
	c.ok("welcome back, %s.", bold(session.User.Username))
	c.printUser()
	return nil
}

func (c *CLI) cmdLogout(ctx context.Context, _ []string) error {
	if err := c.auth.Logout(ctx, c.session.Token); err != nil {
		return err
	}
	c.session = nil
	c.ok("logged out.")
	return nil
}

func (c *CLI) cmdWhoami(context.Context, []string) error {
	c.printUser()
	return nil
}

func (c *CLI) cmdEnable2FA(ctx context.Context, _ []string) error {
	enrollment, err := c.auth.Begin2FA(c.session.User)
	if err != nil {
		return err
	}
	c.printf("\nScan this QR code with Google Authenticator (or any TOTP app):\n\n")
	qrterminal.GenerateHalfBlock(enrollment.URL, qrterminal.L, c.rl.Stdout())
	c.printf("\nOr enter the secret manually: %s\n\n", bold(enrollment.Secret))

	code, err := c.ask("Enter the 6-digit code to confirm: ")
	if err != nil {
		return err
	}
	if err := c.auth.Confirm2FA(ctx, c.session.User, enrollment, code); err != nil {
		return err
	}
	c.ok("2FA enabled. You will be asked for a code at every login.")
	return nil
}

func (c *CLI) cmdDisable2FA(ctx context.Context, _ []string) error {
	if !c.session.User.TwoFactorEnabled() {
		return auth.Err2FADisabled
	}
	code, err := c.ask("Enter a current 6-digit code to confirm: ")
	if err != nil {
		return err
	}
	if err := c.auth.Disable2FA(ctx, c.session.User, code); err != nil {
		return err
	}
	c.ok("2FA disabled.")
	return nil
}

// --- helpers ---

// Details shown after login and by whoami.
func (c *CLI) printUser() {
	u := c.session.User
	mfa := "disabled"
	if u.TwoFactorEnabled() {
		mfa = "enabled"
	}
	lastLogin := "this is your first login"
	if !c.session.PreviousLogin.IsZero() {
		lastLogin = c.session.PreviousLogin.Local().Format(timeFormat)
	}
	c.printf("\n  %-18s %s\n", "Username:", u.Username)
	c.printf("  %-18s %s\n", "Registered:", u.CreatedAt.Local().Format(timeFormat))
	c.printf("  %-18s %s\n", "MFA status:", mfa)
	c.printf("  %-18s %s (in %s)\n", "Session expires:",
		c.session.ExpiresAt.Local().Format(timeFormat),
		time.Until(c.session.ExpiresAt).Round(time.Second))
	c.printf("  %-18s %s\n\n", "Last login:", lastLogin)
}

// Either "login alice" or a prompt.
func (c *CLI) askUsername(args []string) (string, error) {
	if len(args) > 0 {
		return args[0], nil
	}
	return c.ask("Username: ")
}

func (c *CLI) ask(prompt string) (string, error) {
	c.rl.SetPrompt(prompt)
	line, err := c.rl.Readline()
	if errors.Is(err, readline.ErrInterrupt) || errors.Is(err, io.EOF) {
		return "", errors.New("cancelled")
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func (c *CLI) printf(format string, a ...any) {
	fmt.Fprintf(c.rl.Stdout(), format, a...)
}

func (c *CLI) ok(format string, a ...any) {
	c.printf("%s %s\n", green("✔"), fmt.Sprintf(format, a...))
}

func (c *CLI) fail(err error) {
	fmt.Fprintf(c.rl.Stderr(), "%s %s\n", red("✖"), err)
}

func promptFor(s *auth.Session) string {
	if s == nil {
		return bold("auth") + "> "
	}
	return bold(s.User.Username) + "> "
}

// Completes the command word against whatever is valid right now.
type completer struct{ cli *CLI }

func (c *completer) Do(line []rune, pos int) ([][]rune, int) {
	head := string(line[:pos])
	if strings.ContainsAny(head, " \t") {
		return nil, 0 // arguments are values, nothing to complete
	}
	var matches [][]rune
	for name := range c.cli.commands() {
		if strings.HasPrefix(name, head) {
			matches = append(matches, []rune(name[len(head):]+" "))
		}
	}
	sort.Slice(matches, func(i, j int) bool { return string(matches[i]) < string(matches[j]) })
	return matches, len(head)
}

func historyFile() string {
	if p := os.Getenv("HISTORY_FILE"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(os.TempDir(), ".cli-login-history")
	}
	return filepath.Join(home, ".cli-login-history")
}

// Off when redirected or NO_COLOR is set.
var colorOK = os.Getenv("NO_COLOR") == "" && readline.IsTerminal(int(os.Stdout.Fd()))

func paint(code, s string) string {
	if !colorOK {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func bold(s string) string  { return paint("1", s) }
func green(s string) string { return paint("32", s) }
func red(s string) string   { return paint("31", s) }
