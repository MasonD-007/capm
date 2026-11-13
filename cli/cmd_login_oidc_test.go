package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	idJWT    = "eyJhbGciOiJSUzI1NiJ9.eyJmYWtlIjoxfQ.c2ln" // the (fake) GitHub ID token
	reqToken = "actions-request-token-xyz"                // ACTIONS_ID_TOKEN_REQUEST_TOKEN
	regToken = "registry-ci-token-777"                    // what the registry mints
)

// oidcWorld is a fake Actions token endpoint plus a fake registry.
type oidcWorld struct {
	actions *httptest.Server
	reg     *httptest.Server

	mu          sync.Mutex
	actionsReqs []*http.Request
	idQuery     url.Values
	idAuth      string
	exchanged   string // the ID token the registry received
	regStatus   int
	regBody     string
	redirectTo  string
}

func newOIDCWorld(t *testing.T) *oidcWorld {
	w := &oidcWorld{regStatus: 200}
	w.actions = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.mu.Lock()
		w.actionsReqs = append(w.actionsReqs, r)
		w.idQuery, w.idAuth = r.URL.Query(), r.Header.Get("Authorization")
		redirect := w.redirectTo
		w.mu.Unlock()
		if redirect != "" {
			http.Redirect(rw, r, redirect, 302)
			return
		}
		json.NewEncoder(rw).Encode(map[string]string{"value": idJWT})
	}))
	w.reg = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/v1/auth/oidc" {
			rw.WriteHeader(404)
			return
		}
		var in struct{ Token string }
		json.NewDecoder(r.Body).Decode(&in)
		w.mu.Lock()
		w.exchanged = in.Token
		status, body := w.regStatus, w.regBody
		w.mu.Unlock()
		if body == "" {
			body = `{"token":"` + regToken + `","expiresAt":"2026-11-12T12:15:00Z","login":"alice"}`
		}
		rw.WriteHeader(status)
		io.WriteString(rw, body)
	}))
	t.Cleanup(w.actions.Close)
	t.Cleanup(w.reg.Close)
	return w
}

func (w *oidcWorld) hits() int { w.mu.Lock(); defer w.mu.Unlock(); return len(w.actionsReqs) }

type oidcRun struct {
	e    env
	out  bytes.Buffer
	errb bytes.Buffer
}

// newOIDCRun wires an env that treats the fake Actions server as an Actions
// host (the real check is tested separately, below).
func newOIDCRun(t *testing.T, w *oidcWorld, vars map[string]string) *oidcRun {
	if vars == nil {
		vars = map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": w.actions.URL + "/idtoken?api-version=2.0", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": reqToken}
	}
	return &oidcRun{e: env{registry: w.reg.URL, credDir: filepath.Join(t.TempDir(), "capm"),
		getenv:       func(k string) string { return vars[k] },
		actionsHosts: func(*url.URL) bool { return true }}}
}

func (r *oidcRun) run(args ...string) int {
	r.out.Reset()
	r.errb.Reset()
	return runEnv(append([]string{"login"}, args...), &r.out, &r.errb, r.e)
}

func (r *oidcRun) noSecretsInStderr(t *testing.T) {
	t.Helper()
	for _, s := range []string{idJWT, reqToken, regToken} {
		if strings.Contains(r.errb.String(), s) {
			t.Fatalf("stderr contains a secret (%q): %s", s, r.errb.String())
		}
	}
}

func TestLoginOIDCPrintsOnlyTheRegistryTokenToStdout(t *testing.T) {
	w := newOIDCWorld(t)
	r := newOIDCRun(t, w, nil)
	if code := r.run("--oidc"); code != 0 {
		t.Fatalf("exit %d: %s", code, r.errb.String())
	}
	if r.out.String() != regToken+"\n" {
		t.Fatalf("stdout %q", r.out.String())
	}
	r.noSecretsInStderr(t)
	if r.errb.Len() == 0 {
		t.Fatal("expected human text on stderr")
	}
	if _, err := os.Stat(filepath.Join(r.e.credDir, "credentials.json")); err == nil {
		t.Fatal("login --oidc wrote the credentials file")
	}
	// The request token went to the Actions endpoint as a bearer, the ID
	// token went to the registry, never the other way round.
	if w.idAuth != "Bearer "+reqToken || w.exchanged != idJWT {
		t.Fatalf("auth %q exchanged %q", w.idAuth, w.exchanged)
	}
	// The existing query parameters are kept and the audience (the registry
	// base URL by default) is appended, URL-encoded.
	if w.idQuery.Get("api-version") != "2.0" || w.idQuery.Get("audience") != w.reg.URL {
		t.Fatalf("query %v", w.idQuery)
	}
}

func TestLoginOIDCAudienceFlagAndEncoding(t *testing.T) {
	w := newOIDCWorld(t)
	r := newOIDCRun(t, w, nil)
	aud := "https://capm.example/a b&c=d"
	if code := r.run("--oidc", "--audience", aud); code != 0 {
		t.Fatalf("exit %d: %s", code, r.errb.String())
	}
	if w.idQuery.Get("audience") != aud || len(w.idQuery["audience"]) != 1 {
		t.Fatalf("audience %v", w.idQuery)
	}
	if !strings.Contains(w.actionsReqs[0].URL.RawQuery, "audience="+url.QueryEscape(aud)) {
		t.Fatalf("raw query %q", w.actionsReqs[0].URL.RawQuery)
	}
}

func TestLoginOIDCDefaultAudienceTrimsTrailingSlash(t *testing.T) {
	w := newOIDCWorld(t)
	r := newOIDCRun(t, w, nil)
	r.e.registry = w.reg.URL + "/"
	if code := r.run("--oidc"); code != 0 {
		t.Fatalf("exit %d: %s", code, r.errb.String())
	}
	if w.idQuery.Get("audience") != w.reg.URL {
		t.Fatalf("audience %q", w.idQuery.Get("audience"))
	}
}

func TestLoginOIDCRequestURLWithoutQuery(t *testing.T) {
	w := newOIDCWorld(t)
	r := newOIDCRun(t, w, map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": w.actions.URL + "/idtoken", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": reqToken})
	if code := r.run("--oidc"); code != 0 {
		t.Fatalf("exit %d: %s", code, r.errb.String())
	}
	if w.idQuery.Get("audience") != w.reg.URL {
		t.Fatalf("%v", w.idQuery)
	}
}

func TestLoginOIDCOutsideActionsNamesThePermission(t *testing.T) {
	w := newOIDCWorld(t)
	for _, vars := range []map[string]string{
		{}, {"ACTIONS_ID_TOKEN_REQUEST_URL": w.actions.URL}, {"ACTIONS_ID_TOKEN_REQUEST_TOKEN": reqToken},
	} {
		r := newOIDCRun(t, w, vars)
		if code := r.run("--oidc"); code != 1 {
			t.Fatalf("exit %d", code)
		}
		s := r.errb.String()
		if !strings.Contains(s, "id-token: write") || !strings.Contains(s, "ACTIONS_ID_TOKEN_REQUEST") || r.out.Len() != 0 {
			t.Fatalf("stderr %q stdout %q", s, r.out.String())
		}
	}
	if w.hits() != 0 {
		t.Fatal("made a request without the environment")
	}
}

func TestLoginOIDCRefusesNonActionsHostsBeforeSendingTheRequestToken(t *testing.T) {
	w := newOIDCWorld(t)
	// Default env: the real host check. The fake is a loopback server.
	r := newOIDCRun(t, w, nil)
	r.e.actionsHosts = nil
	if code := r.run("--oidc"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if w.hits() != 0 {
		t.Fatal("the request token was sent to a non-Actions host")
	}
	if !strings.Contains(r.errb.String(), "refusing") || r.out.Len() != 0 {
		t.Fatalf("stderr %q", r.errb.String())
	}
	r.noSecretsInStderr(t)
}

func TestActionsURLCheck(t *testing.T) {
	good := []string{
		"https://run-actions-1-azure-eastus.actions.githubusercontent.com/38//idtoken/a/b?api-version=2.0",
		"https://pipelines.actions.githubusercontent.com/x",
		"https://A.Actions.GitHubUserContent.com/x", // host names are case-insensitive
		"https://x.actions.githubusercontent.com:443/x",
	}
	bad := []string{
		"", "not a url", "/relative",
		"http://x.actions.githubusercontent.com/x",          // plain http
		"https://actions.githubusercontent.com/x",           // the bare domain is not a subdomain
		"https://githubusercontent.com/x",                   //
		"https://evil.com/x",                                //
		"https://x.actions.githubusercontent.com.evil.com/", // suffix trick
		"https://evilactions.githubusercontent.com/x",       // no dot boundary
		"https://x.actions.githubusercontent.com@evil.com/x",
		"https://user:pw@x.actions.githubusercontent.com/x", // credentials
		"https://x.actions.githubusercontent.com:8443/x",    // odd port
		"https://x.actions.githubusercontent.com./x",        // rooted name
		"https://127.0.0.1/x",
		"https://[::1]/x",
		"ftp://x.actions.githubusercontent.com/x",
		"https://x.actions.githubusercontent.com\\@evil.com/x",
	}
	for _, s := range good {
		if err := checkActionsURL(s); err != nil {
			t.Errorf("%q refused: %v", s, err)
		}
	}
	for _, s := range bad {
		if err := checkActionsURL(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestLoginOIDCDoesNotFollowRedirectsWithTheRequestToken(t *testing.T) {
	w := newOIDCWorld(t)
	other := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		t.Errorf("redirect target was contacted (auth %q)", r.Header.Get("Authorization"))
	}))
	defer other.Close()
	w.redirectTo = other.URL
	r := newOIDCRun(t, w, nil)
	if code := r.run("--oidc"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	r.noSecretsInStderr(t)
}

func TestLoginOIDCExchangeRefusalIsShownAndNothingPrintedToStdout(t *testing.T) {
	w := newOIDCWorld(t)
	w.regStatus, w.regBody = 403, `{"error":"organisation namespaces are not supported yet"}`
	r := newOIDCRun(t, w, nil)
	if code := r.run("--oidc"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(r.errb.String(), "organisation namespaces are not supported yet") || r.out.Len() != 0 {
		t.Fatalf("stderr %q stdout %q", r.errb.String(), r.out.String())
	}
	r.noSecretsInStderr(t)
}

func TestLoginOIDCOlderRegistry(t *testing.T) {
	w := newOIDCWorld(t)
	w.regStatus, w.regBody = 404, `{"error":"not found"}`
	r := newOIDCRun(t, w, nil)
	if code := r.run("--oidc"); code != 1 || !strings.Contains(r.errb.String(), "does not support") {
		t.Fatalf("exit %d: %s", code, r.errb.String())
	}
}

func TestLoginOIDCBadRegistryReply(t *testing.T) {
	for _, body := range []string{`{}`, `{"token":""}`, `{"token":"has space"}`, `not json`} {
		w := newOIDCWorld(t)
		w.regBody = body
		r := newOIDCRun(t, w, nil)
		if code := r.run("--oidc"); code != 1 || r.out.Len() != 0 {
			t.Errorf("%q: exit %d stdout %q", body, code, r.out.String())
		}
	}
}

func TestLoginFlagUsage(t *testing.T) {
	w := newOIDCWorld(t)
	r := newOIDCRun(t, w, nil)
	for _, args := range [][]string{{"--audience", "x"}, {"--oidc", "extra"}, {"--bogus"}, {"--oidc", "--audience"}, {"--oidc", "--audience", ""}} {
		if code := r.run(args...); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
	if w.hits() != 0 {
		t.Fatal("usage error made a request")
	}
}
