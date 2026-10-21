package auth_test

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/MasonD-007/capm/backend/internal/api"
	"github.com/MasonD-007/capm/backend/internal/auth"
	"github.com/MasonD-007/capm/backend/internal/store"
	"github.com/MasonD-007/capm/manifest"
)

var _ = tar.TypeReg

const ghToken = "gho_FAKE_GITHUB_ACCESS_TOKEN"

// fakeGitHub models device flow and /user.
type fakeGitHub struct {
	mu     sync.Mutex
	state  string // "" = ok, else error code returned by access_token
	id     int64
	login  string
	srv    *httptest.Server
	gotCID string
}

func newFakeGitHub(t *testing.T) *fakeGitHub {
	f := &fakeGitHub{id: 42, login: "alice"}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/device/code", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		f.gotCID = r.Form.Get("client_id")
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"device_code": "dc1", "user_code": "ABCD-1234",
			"verification_uri": "https://github.com/login/device", "interval": 5, "expires_in": 900})
	})
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Form.Get("device_code") != "dc1" || r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
			json.NewEncoder(w).Encode(map[string]string{"error": "bad_device_code"})
			return
		}
		if f.state != "" {
			json.NewEncoder(w).Encode(map[string]string{"error": f.state})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"access_token": ghToken, "token_type": "bearer"})
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+ghToken {
			w.WriteHeader(401)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]any{"id": f.id, "login": f.login})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGitHub) set(state string, id int64, login string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state, f.id, f.login = state, id, login
}

type env struct {
	gh  *fakeGitHub
	srv *httptest.Server
	dir string
}

func setup(t *testing.T, clientID string) *env {
	t.Helper()
	gh := newFakeGitHub(t)
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := auth.New(st, auth.Config{ClientID: clientID, APIURL: gh.srv.URL, OAuthURL: gh.srv.URL})
	reg := api.New(st, svc.Authenticate)
	mux := http.NewServeMux()
	mux.Handle("/v1/auth/", svc.Handler())
	mux.Handle("/v1/", reg.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &env{gh: gh, srv: srv, dir: dir}
}

func (e *env) do(t *testing.T, method, path, token string, body []byte) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (e *env) login(t *testing.T) string {
	t.Helper()
	code, b := e.do(t, "POST", "/v1/auth/token", "", []byte(`{"device_code":"dc1"}`))
	if code != 200 {
		t.Fatalf("token: %d %s", code, b)
	}
	var out struct{ Token string }
	if err := json.Unmarshal(b, &out); err != nil || out.Token == "" {
		t.Fatalf("bad token body %s", b)
	}
	if strings.Contains(string(b), ghToken) {
		t.Fatal("github token leaked")
	}
	return out.Token
}

func bundle(t *testing.T, name, version string) []byte {
	t.Helper()
	dir := t.TempDir()
	y := "apiVersion: capm/v0\nkind: Agent\nmetadata: {name: " + name + ", version: " + version + "}\n" +
		"base: {agent: claude-code, version: 2.1.292}\ninterface: {type: tty}\n" +
		"model: {api: openai-compatible, requires: {toolCalling: true, minContextTokens: 1000}}\n" +
		"permissions: {egress: [api.github.com]}\n"
	os.WriteFile(filepath.Join(dir, manifest.FileName), []byte(y), 0o644)
	b, err := manifest.PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestDeviceStart(t *testing.T) {
	e := setup(t, "cid123")
	code, b := e.do(t, "POST", "/v1/auth/device", "", nil)
	if code != 200 {
		t.Fatalf("%d %s", code, b)
	}
	var out map[string]any
	json.Unmarshal(b, &out)
	if out["device_code"] != "dc1" || out["user_code"] != "ABCD-1234" || out["verification_uri"] == "" || out["interval"] != float64(5) {
		t.Fatalf("%v", out)
	}
	if e.gh.gotCID != "cid123" {
		t.Fatalf("client id %q", e.gh.gotCID)
	}
}

func TestFlowYieldsWorkingToken(t *testing.T) {
	e := setup(t, "cid")
	tok := e.login(t)
	tb := bundle(t, "x", "1.0.0")
	if code, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", tok, tb); code != 201 {
		t.Fatalf("%d %s", code, b)
	}
	if code, _ := e.do(t, "GET", "/v1/bundles/alice/x", "", nil); code != 200 {
		t.Fatal(code)
	}
}

func TestMissingOrGarbageToken(t *testing.T) {
	e := setup(t, "cid")
	e.login(t)
	tb := bundle(t, "x", "1.0.0")
	for _, tok := range []string{"", "garbage", strings.Repeat("A", 43)} {
		if code, _ := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", tok, tb); code != 401 {
			t.Fatalf("token %q: %d", tok, code)
		}
	}
	req, _ := http.NewRequest("PUT", e.srv.URL+"/v1/bundles/alice/x/1.0.0", bytes.NewReader(tb))
	req.Header.Set("Authorization", "Basic abc")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Fatal(resp.StatusCode)
	}
}

func TestGitHubErrors(t *testing.T) {
	e := setup(t, "cid")
	cases := map[string]int{
		"authorization_pending": 428,
		"slow_down":             429,
		"expired_token":         400,
		"access_denied":         403,
		"something_weird":       502,
	}
	for gh, want := range cases {
		e.gh.set(gh, 42, "alice")
		code, b := e.do(t, "POST", "/v1/auth/token", "", []byte(`{"device_code":"dc1"}`))
		if code != want {
			t.Fatalf("%s: %d %s", gh, code, b)
		}
		var out map[string]string
		json.Unmarshal(b, &out)
		if gh != "something_weird" && out["error"] != gh {
			t.Fatalf("%s: body %s", gh, b)
		}
	}
}

func TestTokenRequestValidation(t *testing.T) {
	e := setup(t, "cid")
	for _, body := range []string{``, `{}`, `not json`, `{"device_code":""}`} {
		if code, _ := e.do(t, "POST", "/v1/auth/token", "", []byte(body)); code != 400 {
			t.Fatalf("%q: %d", body, code)
		}
	}
}

func TestRenameKeepsOwnership(t *testing.T) {
	e := setup(t, "cid")
	tok := e.login(t)
	if code, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", tok, bundle(t, "x", "1.0.0")); code != 201 {
		t.Fatalf("%d %s", code, b)
	}
	// Same GitHub id, new login.
	e.gh.set("", 42, "alicia")
	tok2 := e.login(t)
	if code, _ := e.do(t, "GET", "/v1/bundles/alicia/x", "", nil); code != 200 {
		t.Fatalf("new login does not resolve: %d", code)
	}
	if code, _ := e.do(t, "GET", "/v1/bundles/alice/x", "", nil); code != 404 {
		t.Fatalf("old login still resolves: %d", code)
	}
	// Old token now publishes under the new login.
	if code, _ := e.do(t, "PUT", "/v1/bundles/alice/x/1.1.0", tok, bundle(t, "x", "1.1.0")); code != 403 {
		t.Fatalf("old login publish: %d", code)
	}
	if code, b := e.do(t, "PUT", "/v1/bundles/alicia/x/1.1.0", tok, bundle(t, "x", "1.1.0")); code != 201 {
		t.Fatalf("old token under new login: %d %s", code, b)
	}
	if code, b := e.do(t, "PUT", "/v1/bundles/alicia/x/1.2.0", tok2, bundle(t, "x", "1.2.0")); code != 201 {
		t.Fatalf("%d %s", code, b)
	}
	code, b := e.do(t, "GET", "/v1/bundles/alicia/x", "", nil)
	var vs []map[string]any
	json.Unmarshal(b, &vs)
	if code != 200 || len(vs) != 3 {
		t.Fatalf("%d %s", code, b)
	}
}

func TestLoginTakenByAnotherUser(t *testing.T) {
	e := setup(t, "cid")
	e.login(t) // id 42 = alice
	e.gh.set("", 99, "alice")
	tok := e.login(t) // login reassigned to id 99
	if code, b := e.do(t, "PUT", "/v1/bundles/alice/y/1.0.0", tok, bundle(t, "y", "1.0.0")); code != 201 {
		t.Fatalf("%d %s", code, b)
	}
}

func TestTokensStoredHashed(t *testing.T) {
	e := setup(t, "cid")
	tok := e.login(t)
	e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", tok, bundle(t, "x", "1.0.0"))
	var files int
	filepath.Walk(e.dir, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		files++
		b, _ := os.ReadFile(p)
		if bytes.Contains(b, []byte(tok)) {
			t.Errorf("raw capm token found in %s", p)
		}
		if bytes.Contains(b, []byte(ghToken)) {
			t.Errorf("github token found in %s", p)
		}
		return nil
	})
	if files == 0 {
		t.Fatal("no files scanned")
	}
}

func TestNoClientID(t *testing.T) {
	e := setup(t, "")
	for _, p := range []string{"/v1/auth/device", "/v1/auth/token"} {
		code, b := e.do(t, "POST", p, "", []byte(`{"device_code":"dc1"}`))
		var out map[string]string
		json.Unmarshal(b, &out)
		if code != 503 || out["error"] == "" {
			t.Fatalf("%s: %d %s", p, code, b)
		}
	}
}
