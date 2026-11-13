package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	"github.com/MasonD-007/capm/cli/internal/client"
)

// credentials is the on-disk login state. The token is only valid for the
// registry it was issued by, so that is recorded and checked.
type credentials struct {
	Registry string `json:"registry"`
	Login    string `json:"login"`
	Token    string `json:"token"`
	// ExpiresAt is the token's expiry (RFC 3339), empty when it never expires
	// or the file predates expiry.
	ExpiresAt string `json:"expiresAt,omitempty"`
	// fromEnv marks credentials that came from CAPM_TOKEN rather than the
	// file. It is never serialised: an environment token is never saved.
	fromEnv bool
}

func credPath(e env) (string, error) {
	if e.credDir == "" {
		return "", errors.New("cannot determine a config directory for credentials")
	}
	return filepath.Join(e.credDir, "credentials.json"), nil
}

func saveCreds(e env, c credentials) error {
	p, err := credPath(e)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(e.credDir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(e.credDir, ".credentials-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

var errNotLoggedIn = errors.New("not logged in to this registry: run capm login")

// envToken is CAPM_TOKEN, trimmed ("" when unset or empty).
func (e env) envToken() string { return strings.TrimSpace(e.getEnv("CAPM_TOKEN")) }

// loadCreds is the credential for e.registry: CAPM_TOKEN when it is set and
// non-empty (for CI; used instead of the file, never written), else the
// stored login. CAPM_OWNER names the GitHub login an env token publishes as;
// a publish-only CI token cannot be asked (see withLogin).
func loadCreds(e env) (credentials, error) {
	tok := e.envToken()
	if tok == "" {
		return loadCredsFile(e)
	}
	if strings.IndexFunc(tok, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return credentials{}, errors.New("CAPM_TOKEN contains whitespace or control characters")
	}
	c := credentials{Registry: e.registry, Token: tok, fromEnv: true}
	if o := strings.TrimSpace(e.getEnv("CAPM_OWNER")); o != "" {
		if !segRe.MatchString(o) {
			return credentials{}, errors.New("CAPM_OWNER is not a valid GitHub login")
		}
		c.Login = o
	}
	return c, nil
}

// targetOwner is the namespace a command acts under: --owner (flagOwner, set
// when given, even if empty), else CAPM_OWNER, else the login of the stored
// token. An organisation is named with --owner or CAPM_OWNER; whether the
// caller may publish there is the registry's decision, never cached here.
func targetOwner(e env, c credentials, flagOwner string, flagSet bool) (string, error) {
	if flagSet {
		if !segRe.MatchString(flagOwner) {
			return "", errors.New("--owner is not a valid GitHub login or organisation name")
		}
		return flagOwner, nil
	}
	if o := strings.TrimSpace(e.getEnv("CAPM_OWNER")); o != "" {
		if !segRe.MatchString(o) {
			return "", errors.New("CAPM_OWNER is not a valid GitHub login")
		}
		return o, nil
	}
	return c.Login, nil
}

// withLogin fills in Login for credentials that lack it (an env token without
// CAPM_OWNER) by asking the registry. A publish-scoped token is refused there,
// and the error says to set CAPM_OWNER.
func (c credentials) withLogin(e env) (credentials, error) {
	if c.Login != "" {
		return c, nil
	}
	id, err := client.New(e.registry, c.Token).Me()
	if err != nil {
		return c, fmt.Errorf("cannot tell which GitHub login CAPM_TOKEN belongs to (%v); set CAPM_OWNER to the login that owns the bundle namespace", err)
	}
	if !segRe.MatchString(id.Login) {
		return c, errors.New("the registry returned an invalid login for CAPM_TOKEN")
	}
	c.Login = id.Login
	return c, nil
}

// loadCredsFile reads the stored credentials for e.registry.
func loadCredsFile(e env) (credentials, error) {
	var c credentials
	p, err := credPath(e)
	if err != nil {
		return c, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return c, errNotLoggedIn
	}
	if err != nil {
		return c, err
	}
	if json.Unmarshal(b, &c) != nil || c.Token == "" || c.Login == "" || c.Registry != e.registry {
		return c, errNotLoggedIn
	}
	return c, nil
}

// deleteCreds removes the stored credentials. A missing file is not an error.
func deleteCreds(e env) error {
	p, err := credPath(e)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// warnWindow is how close to expiry the CLI starts nagging.
const warnWindow = 7 * 24 * time.Hour

// expiryWarning returns the one-line warning for creds, or "" when the token
// never expires, is not within warnWindow of expiring, is already expired
// (the server's 401 says so) or the stored date is unreadable. It uses only
// the stored date, so it costs no request.
func expiryWarning(c credentials, now time.Time) string {
	if c.ExpiresAt == "" {
		return ""
	}
	exp, err := time.Parse(time.RFC3339, c.ExpiresAt)
	if err != nil {
		return ""
	}
	left := exp.Sub(now)
	if left <= 0 || left >= warnWindow {
		return ""
	}
	days := int((left + 24*time.Hour - 1) / (24 * time.Hour)) // round up
	unit := "days"
	if days == 1 {
		unit = "day"
	}
	return fmt.Sprintf("your capm token expires in %d %s; run capm login\n", days, unit)
}

// warnExpiry prints the warning, if any, to stderr. Commands that
// authenticate defer it right after loading credentials so it lands after
// their own output.
func warnExpiry(stderr io.Writer, e env, c credentials) {
	now := time.Now
	if e.now != nil {
		now = e.now
	}
	if w := expiryWarning(c, now()); w != "" {
		fmt.Fprint(stderr, w)
	}
}
