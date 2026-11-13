package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// orgRegistry is a stand-in for the registry's login, organisation and
// publish routes that records what the CLI sends.
type orgRegistry struct {
	srv *httptest.Server
	mu  sync.Mutex

	deviceBody, tokenBody []byte
	polls                 int
	supportsOrgs          bool   // reply to {"orgs":true} with scope read:org like a new registry
	tokenOrgs             any    // the "orgs" member of the token reply
	orgsStatus            int    // GET /v1/auth/orgs status (0 = 200)
	orgsBody              string // its body
	pushPath, pushAuth    string
	pushStatus            int
	pushMsg               string
	usageQuery            string
	versionsPath          string
	versionsStatus        int
}

func newOrgRegistry(t *testing.T) *orgRegistry {
	r := &orgRegistry{supportsOrgs: true, orgsBody: `[]`}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/device", func(w http.ResponseWriter, q *http.Request) {
		b, _ := io.ReadAll(q.Body)
		r.mu.Lock()
		r.deviceBody = b
		sup := r.supportsOrgs
		r.mu.Unlock()
		out := map[string]any{"device_code": "dc", "user_code": "ABCD-1234", "verification_uri": "https://example.test/device", "interval": 1, "expires_in": 900}
		if sup && strings.Contains(string(b), `"orgs":true`) {
			out["scope"] = "read:org"
		}
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("POST /v1/auth/token", func(w http.ResponseWriter, q *http.Request) {
		b, _ := io.ReadAll(q.Body)
		r.mu.Lock()
		r.tokenBody = b
		r.polls++
		orgs := r.tokenOrgs
		r.mu.Unlock()
		out := map[string]any{"token": "tok-1"}
		if orgs != nil {
			out["orgs"] = orgs
		}
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /v1/auth/me", func(w http.ResponseWriter, q *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"id": 7, "login": "alice"})
	})
	mux.HandleFunc("GET /v1/auth/orgs", func(w http.ResponseWriter, q *http.Request) {
		r.mu.Lock()
		st, body := r.orgsStatus, r.orgsBody
		r.mu.Unlock()
		if st != 0 {
			w.WriteHeader(st)
		}
		io.WriteString(w, body)
	})
	mux.HandleFunc("GET /v1/auth/usage", func(w http.ResponseWriter, q *http.Request) {
		r.mu.Lock()
		r.usageQuery = q.URL.RawQuery
		r.mu.Unlock()
		io.WriteString(w, `{"bytes":1,"maxBytes":100,"bundles":1,"maxBundles":5,"maxBundleVersions":9}`)
	})
	mux.HandleFunc("PUT /v1/bundles/{owner}/{name}/{version}", func(w http.ResponseWriter, q *http.Request) {
		io.Copy(io.Discard, q.Body)
		r.mu.Lock()
		r.pushPath, r.pushAuth = q.URL.Path, q.Header.Get("Authorization")
		st, msg := r.pushStatus, r.pushMsg
		r.mu.Unlock()
		if st != 0 {
			w.WriteHeader(st)
			json.NewEncoder(w).Encode(map[string]string{"error": msg})
			return
		}
		w.WriteHeader(201)
		io.WriteString(w, `{}`)
	})
	mux.HandleFunc("GET /v1/bundles/{owner}/{name}", func(w http.ResponseWriter, q *http.Request) {
		r.mu.Lock()
		r.versionsPath = q.URL.Path
		st := r.versionsStatus
		r.mu.Unlock()
		if st != 0 {
			w.WriteHeader(st)
			io.WriteString(w, `{"error":"bundle not found"}`)
			return
		}
		io.WriteString(w, `[{"version":"1.0.0","digest":"sha256:x","yanked":false}]`)
	})
	r.srv = httptest.NewServer(mux)
	t.Cleanup(r.srv.Close)
	return r
}

type orgHarness struct {
	reg *orgRegistry
	env env
}

func newOrgHarness(t *testing.T, loggedIn bool) *orgHarness {
	reg := newOrgRegistry(t)
	e := env{registry: reg.srv.URL, credDir: filepath.Join(t.TempDir(), "capm"), sleep: func(time.Duration) {},
		getenv: func(string) string { return "" }}
	if loggedIn {
		if err := saveCreds(e, credentials{Registry: e.registry, Login: "alice", Token: "tok-1"}); err != nil {
			t.Fatal(err)
		}
	}
	return &orgHarness{reg, e}
}

func (h *orgHarness) run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := runEnv(args, &out, &errb, h.env)
	return code, out.String(), errb.String()
}

func TestPlainLoginSendsTheSameDeviceRequestAsBefore(t *testing.T) {
	h := newOrgHarness(t, false)
	code, out, errs := h.run("login")
	if code != 0 {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	if string(h.reg.deviceBody) != "{}" {
		t.Fatalf("device body %q, want {}", h.reg.deviceBody)
	}
	var tb map[string]any
	json.Unmarshal(h.reg.tokenBody, &tb)
	if _, has := tb["orgs"]; has {
		t.Fatalf("plain login asks for orgs: %s", h.reg.tokenBody)
	}
	if strings.Contains(out, "rganisation") {
		t.Fatalf("plain login talks about organisations: %q", out)
	}
}

func TestLoginOrgsAsksForOrgsAndPrintsWhatWasRecorded(t *testing.T) {
	h := newOrgHarness(t, false)
	h.reg.tokenOrgs = map[string]any{"complete": true, "recorded": []map[string]string{
		{"org": "acme", "role": "admin"}, {"org": "initech", "role": "member"}}}
	code, out, errs := h.run("login", "--orgs")
	if code != 0 {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	if string(h.reg.deviceBody) != `{"orgs":true}` {
		t.Fatalf("device body %q", h.reg.deviceBody)
	}
	var tb map[string]any
	json.Unmarshal(h.reg.tokenBody, &tb)
	if tb["orgs"] != true || tb["device_code"] != "dc" {
		t.Fatalf("token body %s", h.reg.tokenBody)
	}
	for _, want := range []string{"Logged in as alice", "acme", "owner", "initech", "member", "24 hours", "capm login --orgs"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out+errs, "tok-1") {
		t.Fatal("token printed")
	}
}

func TestLoginOrgsReportsIncompleteChecksAndEmptyResults(t *testing.T) {
	h := newOrgHarness(t, false)
	h.reg.tokenOrgs = map[string]any{"complete": false, "note": "not all of your organisations were checked \x1b[31m(too many)", "recorded": []map[string]string{}}
	code, out, errs := h.run("login", "--orgs")
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	if !strings.Contains(errs, "not all of your organisations were checked") || strings.Contains(out+errs, "\x1b") {
		t.Fatalf("note not shown or not sanitised: %q %q", out, errs)
	}
	if !strings.Contains(out, "No organisation") {
		t.Fatalf("empty result not explained: %q", out)
	}
}

func TestLoginOrgsAgainstAnOlderRegistryStopsBeforeSigningIn(t *testing.T) {
	h := newOrgHarness(t, false)
	h.reg.supportsOrgs = false // the reply has no scope echo
	code, _, errs := h.run("login", "--orgs")
	if code != 1 || !strings.Contains(errs, "does not support") || h.reg.polls != 0 {
		t.Fatalf("%d %q polls=%d", code, errs, h.reg.polls)
	}
	// And no credentials were stored.
	if _, err := loadCredsFile(h.env); err == nil {
		t.Fatal("credentials stored")
	}
}

func TestLoginOrgsRegistryThatLeavesOutTheOrgsResultSaysSo(t *testing.T) {
	h := newOrgHarness(t, false)
	code, out, errs := h.run("login", "--orgs") // tokenOrgs nil
	if code != 0 || !strings.Contains(errs, "did not report") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
}

func TestLoginRejectsOrgsWithOIDC(t *testing.T) {
	h := newOrgHarness(t, false)
	if code, _, errs := h.run("login", "--oidc", "--orgs"); code != 2 || !strings.Contains(errs, "usage: capm login") {
		t.Fatalf("%d %q", code, errs)
	}
}

func TestOrgsCommandListsRecordedOrganisations(t *testing.T) {
	h := newOrgHarness(t, true)
	exp := time.Now().Add(20 * time.Hour).UTC().Format(time.RFC3339)
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	h.reg.orgsBody = `[{"org":"acme","role":"admin","checkedAt":"` + old + `","expiresAt":"` + exp + `","expired":false},
		{"org":"bad\u001b[31mname","role":"member","checkedAt":"` + old + `","expiresAt":"` + old + `","expired":true}]`
	code, out, errs := h.run("orgs")
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	for _, want := range []string{"ORGANISATION", "acme", "owner", "expired"} {
		if !strings.Contains(out, want) {
			t.Errorf("lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Fatalf("escape reached the terminal: %q", out)
	}
	if !strings.Contains(errs, "capm login --orgs") { // one organisation is stale
		t.Fatalf("no hint to refresh: %q", errs)
	}
}

func TestOrgsCommandEmptyOlderRegistryAndLoggedOut(t *testing.T) {
	h := newOrgHarness(t, true)
	if code, out, _ := h.run("orgs"); code != 0 || !strings.Contains(out, "No organisations") {
		t.Fatalf("empty: %d %q", code, out)
	}
	h.reg.orgsStatus, h.reg.orgsBody = 404, "404 page not found\n"
	if code, _, errs := h.run("orgs"); code != 1 || !strings.Contains(errs, "does not support organisations") {
		t.Fatalf("older registry: %d %q", code, errs)
	}
	if code, _, errs := h.run("orgs", "extra"); code != 2 || !strings.Contains(errs, "usage: capm orgs") {
		t.Fatalf("usage: %d %q", code, errs)
	}
	out := newOrgHarness(t, false)
	if code, _, errs := out.run("orgs"); code != 1 || !strings.Contains(errs, "not logged in") {
		t.Fatalf("logged out: %d %q", code, errs)
	}
}

func TestPushOwnerPublishesUnderTheOrg(t *testing.T) {
	h := newOrgHarness(t, true)
	dir := testBundleDir(t, "agent", "1.0.0")
	for _, args := range [][]string{{"push", "--owner", "acme", dir}, {"push", dir, "--owner=acme"}} {
		code, out, errs := h.run(args...)
		if code != 0 || !strings.Contains(out, "Published acme/agent@1.0.0") {
			t.Fatalf("%v: %d %q %q", args, code, out, errs)
		}
		if h.reg.pushPath != "/v1/bundles/acme/agent/1.0.0" || h.reg.pushAuth != "Bearer tok-1" {
			t.Fatalf("%q %q", h.reg.pushPath, h.reg.pushAuth)
		}
	}
	// Without it, the stored login is used as before.
	if code, out, _ := h.run("push", dir); code != 0 || !strings.Contains(out, "Published alice/agent@1.0.0") {
		t.Fatalf("%d %q", code, out)
	}
}

func TestPushOwnerFromEnvironmentAndFlagWins(t *testing.T) {
	h := newOrgHarness(t, true)
	h.env.getenv = func(k string) string {
		if k == "CAPM_OWNER" {
			return "globex"
		}
		return ""
	}
	dir := testBundleDir(t, "agent", "1.0.0")
	if code, out, _ := h.run("push", dir); code != 0 || !strings.Contains(out, "Published globex/agent@1.0.0") {
		t.Fatalf("env: %d %q", code, out)
	}
	if code, out, _ := h.run("push", "--owner", "acme", dir); code != 0 || !strings.Contains(out, "Published acme/agent@1.0.0") {
		t.Fatalf("flag over env: %d %q", code, out)
	}
	h.env.getenv = func(k string) string {
		if k == "CAPM_OWNER" {
			return "../evil"
		}
		return ""
	}
	if code, _, errs := h.run("push", dir); code != 1 || !strings.Contains(errs, "CAPM_OWNER") {
		t.Fatalf("bad env: %d %q", code, errs)
	}
}

func TestPushOwnerRefusalIsShownAndBadOwnersStayLocal(t *testing.T) {
	h := newOrgHarness(t, true)
	h.reg.pushStatus, h.reg.pushMsg = 403, "you are not recorded as someone who may publish under acme. Organisation owners can run capm login --orgs"
	dir := testBundleDir(t, "agent", "1.0.0")
	code, out, errs := h.run("push", "--owner", "acme", dir)
	if code != 1 || out != "" || !strings.Contains(errs, "403") || !strings.Contains(errs, "capm login --orgs") {
		t.Fatalf("%d %q %q", code, out, errs)
	}
	h.reg.pushPath = ""
	for _, bad := range []string{"", "a/b", "../x", "-x", "a b"} {
		if code, _, errs := h.run("push", "--owner", bad, dir); code == 0 || !strings.Contains(errs, "--owner") {
			t.Errorf("%q accepted: %d %q", bad, code, errs)
		}
	}
	if h.reg.pushPath != "" {
		t.Fatal("a request was sent for an invalid owner")
	}
}

func TestLintVersionCheckUsesTheOwnerFlag(t *testing.T) {
	h := newOrgHarness(t, true)
	dir := testBundleDir(t, "agent", "1.0.0")
	code, _, errs := h.run("lint", "--owner", "acme", dir)
	if h.reg.versionsPath != "/v1/bundles/acme/agent" {
		t.Fatalf("queried %q (exit %d): %s", h.reg.versionsPath, code, errs)
	}
	if !strings.Contains(errs, "version 1.0.0 already exists on the registry for acme/agent") {
		t.Fatalf("%s", errs)
	}
	if code, _, errs := h.run("lint", "--owner", "../x", dir); code != 2 {
		t.Fatalf("%d %s", code, errs)
	}
}

func TestUsageOwnerFlagSendsOwnerQuery(t *testing.T) {
	h := newOrgHarness(t, true)
	if code, out, errs := h.run("usage", "--owner", "acme"); code != 0 || h.reg.usageQuery != "owner=acme" || !strings.Contains(out, "Bundles:") {
		t.Fatalf("%d %q %q query=%q", code, out, errs, h.reg.usageQuery)
	}
	if code, _, _ := h.run("usage"); code != 0 || h.reg.usageQuery != "" {
		t.Fatalf("plain usage sent %q", h.reg.usageQuery)
	}
	if code, _, errs := h.run("usage", "--owner", "a/b"); code != 2 || !strings.Contains(errs, "usage: capm usage") {
		t.Fatalf("%d %q", code, errs)
	}
}
