package main

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"text/tabwriter"
	"time"

	"github.com/MasonD-007/capm/cli/internal/client"
)

const unsupportedMsg = "this registry does not support token management (it is running an older version)"

// logout revokes the current token on the registry, then deletes the local
// credentials. The local deletion happens whatever the server says: a logout
// that leaves the secret on disk would be worse than one that leaves the token
// alive until it expires.
func logout(args []string, stdout, stderr io.Writer, e env) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: capm logout")
		return 2
	}
	creds, err := loadCreds(e)
	if err != nil {
		if errors.Is(err, errNotLoggedIn) {
			fmt.Fprintf(stderr, "capm logout: not logged in to %s\n", client.Sanitize(e.registry))
			return 0
		}
		fmt.Fprintf(stderr, "capm logout: %v\n", err)
		return 1
	}
	rerr := client.New(e.registry, creds.Token).RevokeCurrentToken()
	if err := deleteCreds(e); err != nil {
		fmt.Fprintf(stderr, "capm logout: could not delete the stored credentials: %v\n", err)
		return 1
	}
	var ae *client.APIError
	switch {
	case rerr == nil:
		fmt.Fprintf(stdout, "Logged out of %s; the token was revoked.\n", client.Sanitize(e.registry))
	case errors.As(rerr, &ae) && ae.Status == 401:
		fmt.Fprintf(stdout, "Logged out of %s (the token was already invalid).\n", client.Sanitize(e.registry))
	case client.IsUnsupported(rerr):
		fmt.Fprintf(stderr, "Logged out locally. %s, so the token could not be revoked and may remain valid until it expires.\n", unsupportedMsg)
	default:
		fmt.Fprintf(stderr, "Logged out locally, but the registry could not be reached or refused the request (%v); the token may remain valid until it expires.\n", rerr)
	}
	return 0
}

const tokensUsage = "usage: capm tokens | capm tokens revoke <id>"

// tokens lists the user's login tokens, or revokes one by id.
func tokens(args []string, stdout, stderr io.Writer, e env) int {
	revoke := false
	var id int64
	switch {
	case len(args) == 0:
	case args[0] == "revoke" && len(args) == 2:
		n, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil || n < 1 {
			fmt.Fprintln(stderr, tokensUsage)
			return 2
		}
		revoke, id = true, n
	default:
		fmt.Fprintln(stderr, tokensUsage)
		return 2
	}
	creds, err := loadCreds(e)
	if err != nil {
		fmt.Fprintf(stderr, "capm tokens: %v\n", err)
		return 1
	}
	defer warnExpiry(stderr, e, creds)
	c := client.New(e.registry, creds.Token)
	list, err := c.Tokens()
	if err != nil {
		return tokensFail(stderr, err)
	}
	if revoke {
		return revokeByID(id, list, c, stdout, stderr, e)
	}
	if len(list) == 0 {
		fmt.Fprintln(stderr, "no active tokens")
		return 0
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, " \tID\tNAME\tCREATED\tLAST USED\tEXPIRES")
	for _, t := range list {
		mark := " "
		if t.Current {
			mark = "*"
		}
		name := client.Sanitize(t.Name)
		if name == "" {
			name = "-"
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%s\t%s\n", mark, t.ID, name,
			day(&t.CreatedAt, "-"), day(t.LastUsedAt, "-"), day(t.ExpiresAt, "never"))
	}
	tw.Flush()
	return 0
}

func day(t *time.Time, empty string) string {
	if t == nil || t.IsZero() {
		return empty
	}
	return t.UTC().Format("2006-01-02")
}

func revokeByID(id int64, list []client.TokenInfo, c *client.Client, stdout, stderr io.Writer, e env) int {
	var target *client.TokenInfo
	for i := range list {
		if list[i].ID == id {
			target = &list[i]
		}
	}
	if target == nil {
		fmt.Fprintf(stderr, "capm tokens: no token with id %d (run capm tokens to list yours)\n", id)
		return 1
	}
	if err := c.RevokeToken(id); err != nil {
		var ae *client.APIError
		if errors.As(err, &ae) && ae.Status == 404 && !client.IsUnsupported(err) {
			fmt.Fprintf(stderr, "capm tokens: no token with id %d\n", id)
			return 1
		}
		return tokensFail(stderr, err)
	}
	fmt.Fprintf(stdout, "Revoked token %d\n", id)
	if target.Current {
		if err := deleteCreds(e); err != nil {
			fmt.Fprintf(stderr, "capm tokens: could not delete the stored credentials: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, "That was this machine's token; you are now logged out.")
	}
	return 0
}

func tokensFail(stderr io.Writer, err error) int {
	var ae *client.APIError
	switch {
	case client.IsUnsupported(err):
		fmt.Fprintf(stderr, "capm tokens: %s\n", unsupportedMsg)
	case errors.As(err, &ae) && ae.Status == 401:
		fmt.Fprintln(stderr, "capm tokens: the stored token is no longer valid; run capm login")
	default:
		fmt.Fprintf(stderr, "capm tokens: %v\n", err)
	}
	return 1
}
