package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MasonD-007/capm/cli/internal/client"
)

// testActionsHosts is a TEST-BUILD-ONLY escape from the Actions host check in
// checkActionsURL. It is a plain string variable that is empty in every
// shipped binary: the only way to set it is the linker flag
//
//	go build -ldflags "-X main.testActionsHosts=127.0.0.1:PORT"
//
// so it cannot be switched on through the environment, a flag or a file, and a
// tampered environment cannot use it. cli-release.yml builds with only
// -X main.version. It exists so the end-to-end harness can point the built
// binary at a fake Actions endpoint without network access. It is not
// documented for users. A binary that has it set says so on every login.
var testActionsHosts = ""

const actionsHostSuffix = ".actions.githubusercontent.com"

// checkActionsURL refuses to send the Actions request token anywhere that is
// not a GitHub Actions host: https, a subdomain of actions.githubusercontent.com
// (case-insensitively, no trailing dot), no credentials, the default port.
// The environment is attacker-influenced in a compromised workflow step, and
// this token can mint an ID token for any audience.
func checkActionsURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("is not a plain absolute URL")
	}
	if testActionsHosts != "" {
		for _, h := range strings.Split(testActionsHosts, ",") {
			if strings.EqualFold(u.Host, strings.TrimSpace(h)) {
				return nil
			}
		}
	}
	host := strings.ToLower(u.Hostname())
	switch {
	case u.Scheme != "https":
		return errors.New("is not an https URL")
	case u.Port() != "" && u.Port() != "443":
		return errors.New("uses an unexpected port")
	case !strings.HasSuffix(host, actionsHostSuffix) || len(host) == len(actionsHostSuffix):
		return errors.New("is not a GitHub Actions host (*.actions.githubusercontent.com)")
	}
	return nil
}

const loginUse = "usage: capm login [--orgs]\n       capm login --oidc [--audience URL]"

// loginOIDC, run inside GitHub Actions, trades the job's OIDC identity for a
// short-lived publish-only registry token. stdout gets the token and nothing
// else (a workflow captures it); everything human goes to stderr. Nothing is
// written to disk, and neither the request token nor the ID token is ever
// printed.
func loginOIDC(audience string, stdout, stderr io.Writer, e env) int {
	reqURL, reqTok := strings.TrimSpace(e.getEnv("ACTIONS_ID_TOKEN_REQUEST_URL")), strings.TrimSpace(e.getEnv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"))
	if reqURL == "" || reqTok == "" {
		fmt.Fprintln(stderr, "capm login --oidc: ACTIONS_ID_TOKEN_REQUEST_URL / ACTIONS_ID_TOKEN_REQUEST_TOKEN are not set.\n"+
			"This works only inside a GitHub Actions job whose workflow grants the permission\n"+
			"  permissions:\n    id-token: write\n"+
			"(at the workflow or job level); without it GitHub does not provide these variables.")
		return 1
	}
	if testActionsHosts != "" {
		fmt.Fprintln(stderr, "capm login --oidc: WARNING: this is a TEST BUILD that accepts non-GitHub token endpoints")
	}
	if e.actionsHosts != nil {
		// Unit tests only (the field is unreachable from the command line).
	} else if err := checkActionsURL(reqURL); err != nil {
		fmt.Fprintf(stderr, "capm login --oidc: refusing to use ACTIONS_ID_TOKEN_REQUEST_URL: it %v; the request token was not sent\n", err)
		return 1
	}
	if audience == "" {
		audience = strings.TrimRight(e.registry, "/")
	}
	sep := "&"
	if !strings.Contains(reqURL, "?") {
		sep = "?"
	}
	req, err := http.NewRequest("GET", reqURL+sep+"audience="+url.QueryEscape(audience), nil)
	if err != nil {
		fmt.Fprintln(stderr, "capm login --oidc: ACTIONS_ID_TOKEN_REQUEST_URL is not a valid URL")
		return 1
	}
	req.Header.Set("Authorization", "Bearer "+reqTok)
	req.Header.Set("Accept", "application/json")
	hc := &http.Client{Timeout: 30 * time.Second,
		// The request token must never follow a redirect to another host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := hc.Do(req)
	if err != nil {
		// err can embed the URL; the URL is not secret but never the token.
		fmt.Fprintln(stderr, "capm login --oidc: could not reach the GitHub Actions token endpoint")
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "capm login --oidc: the GitHub Actions token endpoint answered %d (is `permissions: id-token: write` set?)\n", resp.StatusCode)
		return 1
	}
	var idr struct {
		Value string `json:"value"`
	}
	if b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10)); err != nil || json.Unmarshal(b, &idr) != nil || idr.Value == "" {
		fmt.Fprintln(stderr, "capm login --oidc: the GitHub Actions token endpoint returned no ID token")
		return 1
	}

	c := client.New(e.registry, "")
	res, err := c.OIDCExchange(idr.Value)
	if err != nil {
		var ae *client.APIError
		if errors.As(err, &ae) && ae.Status == http.StatusNotFound {
			fmt.Fprintf(stderr, "capm login --oidc: %s does not support publishing from CI (an older server, or it is switched off)\n", client.Sanitize(e.registry))
		} else {
			fmt.Fprintf(stderr, "capm login --oidc: %v\n", err)
		}
		return 1
	}
	if res.Token == "" || strings.ContainsAny(res.Token, " \t\r\n") {
		fmt.Fprintln(stderr, "capm login --oidc: the registry returned an unusable token")
		return 1
	}
	fmt.Fprintf(stderr, "Exchanged this job's GitHub identity for a publish-only registry token for %s (expires %s)\n",
		client.Sanitize(res.Login), client.Sanitize(res.ExpiresAt))
	fmt.Fprintln(stdout, res.Token)
	return 0
}
