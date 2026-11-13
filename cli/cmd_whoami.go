package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/MasonD-007/capm/cli/internal/client"
)

// whoami prints the login the stored token belongs to. Only the login goes to
// stdout so scripts can use $(capm whoami); the rest is on stderr. Not being
// logged in is decided from the credentials file alone, with no request.
func whoami(args []string, stdout, stderr io.Writer, e env) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: capm whoami")
		return 2
	}
	creds, err := loadCreds(e)
	if err != nil {
		if errors.Is(err, errNotLoggedIn) {
			fmt.Fprintf(stderr, "capm whoami: not logged in to %s; run capm login\n", client.Sanitize(e.registry))
		} else {
			fmt.Fprintf(stderr, "capm whoami: %v\n", err)
		}
		return 1
	}
	id, err := client.New(e.registry, creds.Token).Me()
	if err != nil {
		var ae *client.APIError
		switch {
		case errors.As(err, &ae) && ae.Status == http.StatusUnauthorized && creds.fromEnv:
			fmt.Fprintln(stderr, "capm whoami: the token in CAPM_TOKEN is not valid (or has expired)")
		case errors.As(err, &ae) && ae.Status == http.StatusUnauthorized:
			fmt.Fprintln(stderr, "capm whoami: the stored token is no longer valid; run capm login")
		default:
			fmt.Fprintf(stderr, "capm whoami: %v\n", err)
			if creds.fromEnv && errors.As(err, &ae) && ae.Status == http.StatusForbidden {
				fmt.Fprintln(stderr, "(CAPM_TOKEN is a publish-only CI token: it can publish, but cannot call whoami)")
			}
		}
		return 1
	}
	login := client.Sanitize(id.Login)
	fmt.Fprintf(stderr, "logged in to %s as %s (GitHub ID %d)\n", client.Sanitize(e.registry), login, id.ID)
	if creds.fromEnv {
		fmt.Fprintln(stderr, "(token from CAPM_TOKEN)")
	}
	fmt.Fprintln(stdout, login)
	return 0
}
