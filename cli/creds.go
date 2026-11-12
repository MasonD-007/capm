package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
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

func loadCreds(e env) (credentials, error) {
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
