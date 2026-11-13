package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const ciTok = "ci-registry-token-abc123"

// recReg is a registry stand-in that records requests. scoped makes every
// authenticated route except publish answer like the real server does for a
// publish-scoped token.
type recReg struct {
	srv    *httptest.Server
	mu     sync.Mutex
	reqs   []string // "METHOD path auth"
	scoped bool
	me     string // login /me reports for a full token
}

const scopedMsg = "this token is publish-scoped (issued to a CI workflow) and can only publish bundles under its own login"

func newRecReg(t *testing.T, scoped bool) *recReg {
	f := &recReg{scoped: scoped, me: "alice"}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.reqs = append(f.reqs, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization"))
		f.mu.Unlock()
		io.Copy(io.Discard, r.Body)
		isPublish := r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/v1/bundles/")
		isPublic := r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/bundles/")
		if f.scoped && !isPublish && !isPublic {
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]string{"error": scopedMsg})
			return
		}
		switch {
		case isPublish:
			w.WriteHeader(201)
			w.Write([]byte(`{}`))
		case isPublic:
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"bundle not found"}`))
		case r.URL.Path == "/v1/auth/me":
			json.NewEncoder(w).Encode(map[string]any{"id": 42, "login": f.me})
		case r.URL.Path == "/v1/auth/tokens" && r.Method == "GET":
			fmt.Fprint(w, `[{"id":9,"name":"ci","createdAt":"2026-01-01T00:00:00Z","current":true}]`)
		case strings.HasPrefix(r.URL.Path, "/v1/auth/tokens/") && r.Method == "DELETE":
			w.WriteHeader(204)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *recReg) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

func (f *recReg) count(prefix string) int {
	n := 0
	for _, r := range f.requests() {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

type tokEnvRun struct {
	e    env
	out  bytes.Buffer
	errb bytes.Buffer
}

func newTokEnvRun(t *testing.T, reg *recReg, vars map[string]string) *tokEnvRun {
	r := &tokEnvRun{}
	r.e = env{registry: reg.srv.URL, credDir: filepath.Join(t.TempDir(), "capm"),
		getenv: func(k string) string { return vars[k] }}
	return r
}

func (r *tokEnvRun) run(args ...string) int {
	r.out.Reset()
	r.errb.Reset()
	return runEnv(args, &r.out, &r.errb, r.e)
}

func (r *tokEnvRun) noCredsFile(t *testing.T) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(r.e.credDir, "credentials.json")); err == nil {
		t.Fatal("credentials file was written")
	}
}

func TestCapmTokenPublishesWithoutTouchingTheCredentialsFile(t *testing.T) {
	reg := newRecReg(t, true)
	r := newTokEnvRun(t, reg, map[string]string{"CAPM_TOKEN": ciTok, "CAPM_OWNER": "alice"})
	dir := testBundleDir(t, "x", "1.0.0")
	if code := r.run("push", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, r.errb.String())
	}
	if r.out.String() != "Published alice/x@1.0.0\n" {
		t.Fatalf("stdout %q", r.out.String())
	}
	want := "PUT /v1/bundles/alice/x/1.0.0 Bearer " + ciTok
	if got := reg.requests(); len(got) != 1 || got[0] != want {
		t.Fatalf("requests %v, want only %q (no /me for a publish-scoped token)", got, want)
	}
	r.noCredsFile(t)
	if strings.Contains(r.out.String()+r.errb.String(), ciTok) {
		t.Fatal("token printed")
	}
}

func TestCapmTokenOverridesStoredCredentials(t *testing.T) {
	reg := newRecReg(t, false)
	r := newTokEnvRun(t, reg, map[string]string{"CAPM_TOKEN": ciTok, "CAPM_OWNER": "alice"})
	saveCreds(r.e, credentials{Registry: reg.srv.URL, Login: "bob", Token: "file-token"})
	if code := r.run("push", testBundleDir(t, "x", "1.0.0")); code != 0 {
		t.Fatalf("exit %d: %s", code, r.errb.String())
	}
	if got := reg.requests(); len(got) != 1 || got[0] != "PUT /v1/bundles/alice/x/1.0.0 Bearer "+ciTok {
		t.Fatalf("%v", got)
	}
	// An empty CAPM_TOKEN is "not set": the file is used.
	r2 := newTokEnvRun(t, reg, map[string]string{"CAPM_TOKEN": ""})
	r2.e.credDir = r.e.credDir
	if code := r2.run("push", testBundleDir(t, "x", "1.0.1")); code != 0 {
		t.Fatalf("exit %d: %s", code, r2.errb.String())
	}
	if got := reg.requests(); got[len(got)-1] != "PUT /v1/bundles/bob/x/1.0.1 Bearer file-token" {
		t.Fatalf("%v", got)
	}
}

func TestCapmTokenWithoutOwnerAsksTheRegistryWhoItIs(t *testing.T) {
	reg := newRecReg(t, false) // a full token: /me works
	r := newTokEnvRun(t, reg, map[string]string{"CAPM_TOKEN": ciTok})
	if code := r.run("push", testBundleDir(t, "x", "1.0.0")); code != 0 {
		t.Fatalf("exit %d: %s", code, r.errb.String())
	}
	if reg.count("GET /v1/auth/me") != 1 || reg.count("PUT /v1/bundles/alice/x/1.0.0") != 1 {
		t.Fatalf("%v", reg.requests())
	}
	r.noCredsFile(t)
}

func TestCapmTokenScopedWithoutOwnerExplainsCapmOwner(t *testing.T) {
	reg := newRecReg(t, true)
	r := newTokEnvRun(t, reg, map[string]string{"CAPM_TOKEN": ciTok})
	if code := r.run("push", testBundleDir(t, "x", "1.0.0")); code != 1 {
		t.Fatalf("exit %d", code)
	}
	s := r.errb.String()
	if !strings.Contains(s, "publish-scoped") || !strings.Contains(s, "CAPM_OWNER") {
		t.Fatalf("stderr %q", s)
	}
	if reg.count("PUT") != 0 {
		t.Fatal("published without an owner")
	}
}

func TestCapmOwnerMustBeAValidLogin(t *testing.T) {
	reg := newRecReg(t, true)
	r := newTokEnvRun(t, reg, map[string]string{"CAPM_TOKEN": ciTok, "CAPM_OWNER": "../evil"})
	if code := r.run("push", testBundleDir(t, "x", "1.0.0")); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if len(reg.requests()) != 0 || !strings.Contains(r.errb.String(), "CAPM_OWNER") {
		t.Fatalf("%v %q", reg.requests(), r.errb.String())
	}
}

func TestPushPreflightStillRunsWithCapmToken(t *testing.T) {
	reg := newRecReg(t, true)
	r := newTokEnvRun(t, reg, map[string]string{"CAPM_TOKEN": ciTok, "CAPM_OWNER": "alice"})
	dir := lintBundle(t, map[string]string{"capm.yaml": lintManifest("a", "1.0.0", "cfg/.env"), "cfg/.env": "T=" + fakeGH + "\n"})
	if code := r.run("push", dir); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(r.errb.String(), "error[secret_file]") || len(reg.requests()) != 0 {
		t.Fatalf("%q %v", r.errb.String(), reg.requests())
	}
}

func TestScopedTokenOnOtherCommandsPrintsTheServersMessage(t *testing.T) {
	reg := newRecReg(t, true)
	r := newTokEnvRun(t, reg, map[string]string{"CAPM_TOKEN": ciTok})
	for _, args := range [][]string{{"tokens"}, {"whoami"}, {"usage"}} {
		if code := r.run(args...); code != 1 {
			t.Errorf("%v: exit %d", args, code)
		}
		if !strings.Contains(r.errb.String(), "publish-scoped") {
			t.Errorf("%v: stderr %q", args, r.errb.String())
		}
	}
}

func TestWhoamiWithCapmToken(t *testing.T) {
	reg := newRecReg(t, false)
	r := newTokEnvRun(t, reg, map[string]string{"CAPM_TOKEN": ciTok})
	if code := r.run("whoami"); code != 0 || r.out.String() != "alice\n" {
		t.Fatalf("exit %d out %q err %q", code, r.out.String(), r.errb.String())
	}
	if !strings.Contains(r.errb.String(), "CAPM_TOKEN") {
		t.Fatalf("stderr should say where the credential came from: %q", r.errb.String())
	}
	if got := reg.requests(); len(got) != 1 || got[0] != "GET /v1/auth/me Bearer "+ciTok {
		t.Fatalf("%v", got)
	}
}

// logout with CAPM_TOKEN set does nothing: it neither deletes the stored
// credentials (a different identity, not what the env token is) nor revokes
// the environment's token. It says so and exits 0 so a CI cleanup step does
// not fail.
func TestLogoutWithCapmTokenLeavesEverythingAlone(t *testing.T) {
	reg := newRecReg(t, false)
	r := newTokEnvRun(t, reg, map[string]string{"CAPM_TOKEN": ciTok})
	saveCreds(r.e, credentials{Registry: reg.srv.URL, Login: "bob", Token: "file-token"})
	if code := r.run("logout"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if len(reg.requests()) != 0 {
		t.Fatalf("logout made requests: %v", reg.requests())
	}
	if c, err := loadCredsFile(r.e); err != nil || c.Token != "file-token" {
		t.Fatalf("stored credentials changed: %+v %v", c, err)
	}
	if !strings.Contains(r.errb.String(), "CAPM_TOKEN") || strings.Contains(r.errb.String()+r.out.String(), ciTok) {
		t.Fatalf("stderr %q", r.errb.String())
	}
}

func TestTokensRevokeOfTheEnvTokenKeepsTheCredentialsFile(t *testing.T) {
	reg := newRecReg(t, false)
	r := newTokEnvRun(t, reg, map[string]string{"CAPM_TOKEN": ciTok})
	saveCreds(r.e, credentials{Registry: reg.srv.URL, Login: "bob", Token: "file-token"})
	if code := r.run("tokens", "revoke", "9"); code != 0 {
		t.Fatalf("exit %d: %s", code, r.errb.String())
	}
	if c, err := loadCredsFile(r.e); err != nil || c.Token != "file-token" {
		t.Fatalf("stored credentials were deleted: %+v %v", c, err)
	}
}

func TestLintVersionCheckWorksWithCapmToken(t *testing.T) {
	reg := newRecReg(t, true)
	r := newTokEnvRun(t, reg, map[string]string{"CAPM_TOKEN": ciTok, "CAPM_OWNER": "alice"})
	dir := testBundleDir(t, "x", "1.0.0")
	if code := r.run("lint", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, r.errb.String())
	}
	if reg.count("GET /v1/bundles/alice/x ") != 1 {
		t.Fatalf("lint should have compared versions with the registry: %v", reg.requests())
	}
	if strings.Contains(r.errb.String(), "skipped") {
		t.Fatalf("version check skipped: %s", r.errb.String())
	}
}
