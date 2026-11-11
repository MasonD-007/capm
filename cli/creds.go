package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// credentials is the on-disk login state. The token is only valid for the
// registry it was issued by, so that is recorded and checked.
type credentials struct {
	Registry string `json:"registry"`
	Login    string `json:"login"`
	Token    string `json:"token"`
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
