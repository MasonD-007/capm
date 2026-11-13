package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/MasonD-007/capm/cli/internal/client"
)

func login(args []string, stdout, stderr io.Writer, e env) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var oidc bool
	var audience string
	fs.BoolVar(&oidc, "oidc", false, "")
	fs.StringVar(&audience, "audience", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(stderr, loginUse)
		return 2
	}
	var audSet bool
	fs.Visit(func(f *flag.Flag) { audSet = audSet || f.Name == "audience" })
	if audSet && (!oidc || audience == "") {
		fmt.Fprintln(stderr, loginUse)
		return 2
	}
	if oidc {
		return loginOIDC(audience, stdout, stderr, e)
	}
	c := client.New(e.registry, "")
	if e.sleep != nil {
		c.Sleep = e.sleep
	}
	c.TokenName = tokenName(e)
	dc, err := c.StartDeviceFlow()
	if err != nil {
		fmt.Fprintf(stderr, "capm login: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Open %s and enter the code: %s\nWaiting for authorization...\n", client.Sanitize(dc.VerificationURI), client.Sanitize(dc.UserCode))
	tok, err := c.PollToken(dc.DeviceCode)
	if err != nil {
		fmt.Fprintf(stderr, "capm login: %v\n", err)
		return 1
	}
	id, err := client.New(e.registry, tok).Me()
	if err != nil {
		fmt.Fprintf(stderr, "capm login: %v\n", err)
		return 1
	}
	if !segRe.MatchString(id.Login) {
		fmt.Fprintf(stderr, "capm login: registry returned an invalid login %q\n", client.Sanitize(id.Login))
		return 1
	}
	if err := saveCreds(e, credentials{Registry: e.registry, Login: id.Login, Token: tok, ExpiresAt: id.TokenExpiresAt}); err != nil {
		fmt.Fprintf(stderr, "capm login: saving credentials: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Logged in as %s\n", id.Login)
	return 0
}

// tokenName is the label sent with the login: this machine's hostname, or ""
// when it cannot be determined (naming is best effort).
func tokenName(e env) string {
	h := os.Hostname
	if e.hostname != nil {
		h = e.hostname
	}
	name, err := h()
	if err != nil {
		return ""
	}
	return name
}
