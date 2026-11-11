package main

import (
	"fmt"
	"io"

	"github.com/MasonD-007/capm/cli/internal/client"
)

func login(args []string, stdout, stderr io.Writer, e env) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: capm login")
		return 2
	}
	c := client.New(e.registry, "")
	if e.sleep != nil {
		c.Sleep = e.sleep
	}
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
	if err := saveCreds(e, credentials{Registry: e.registry, Login: id.Login, Token: tok}); err != nil {
		fmt.Fprintf(stderr, "capm login: saving credentials: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Logged in as %s\n", id.Login)
	return 0
}
