package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type tokReq struct{ method, path, auth, body string }

// tokServer records requests and answers with a canned status and body.
type tokServer struct {
	srv    *httptest.Server
	mu     sync.Mutex
	reqs   []tokReq
	status int
	reply  string
}

func (s *tokServer) set(status int, reply string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.status, s.reply = status, reply
}

func (s *tokServer) requests() []tokReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]tokReq(nil), s.reqs...)
}

type tokHarness struct {
	t    *testing.T
	s    *tokServer
	env  env
	cred string
}

func newTokHarness(t *testing.T, loggedIn bool) *tokHarness {
	t.Helper()
	s := &tokServer{status: 200, reply: `{}`}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.reqs = append(s.reqs, tokReq{r.Method, r.URL.RequestURI(), r.Header.Get("Authorization"), string(b)})
		st, rp := s.status, s.reply
		s.mu.Unlock()
		w.WriteHeader(st)
		io.WriteString(w, rp)
	}))
	t.Cleanup(s.srv.Close)
	h := &tokHarness{t: t, s: s}
	h.env = env{registry: s.srv.URL, credDir: filepath.Join(t.TempDir(), "capm")}
	h.cred = filepath.Join(h.env.credDir, "credentials.json")
	if loggedIn {
		h.login(credentials{Registry: s.srv.URL, Login: "alice", Token: "tok-123"})
	}
	return h
}

func (h *tokHarness) login(c credentials) {
	h.t.Helper()
	if err := saveCreds(h.env, c); err != nil {
		h.t.Fatal(err)
	}
}

func (h *tokHarness) hasCreds() bool { _, err := os.Stat(h.cred); return err == nil }

func (h *tokHarness) run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := runEnv(args, &out, &errb, h.env)
	return code, out.String(), errb.String()
}

func TestLogoutRevokesAndDeletesCredentials(t *testing.T) {
	h := newTokHarness(t, true)
	h.s.set(204, "")
	code, out, errb := h.run("logout")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	r := h.s.requests()
	if len(r) != 1 || r[0].method != "DELETE" || r[0].path != "/v1/auth/tokens/current" || r[0].auth != "Bearer tok-123" {
		t.Fatalf("%+v", r)
	}
	if h.hasCreds() {
		t.Fatal("credentials not deleted")
	}
	if !strings.Contains(out, "Logged out") || strings.Contains(out+errb, "tok-123") {
		t.Errorf("out %q err %q", out, errb)
	}
}

func TestLogoutNotLoggedIn(t *testing.T) {
	h := newTokHarness(t, false)
	code, _, errb := h.run("logout")
	if code != 0 || !strings.Contains(errb, "not logged in") {
		t.Fatalf("exit %d, stderr %q", code, errb)
	}
	if len(h.s.requests()) != 0 {
		t.Fatal("made a request while logged out")
	}
}

func TestLogoutLeavesOtherRegistrysCredentials(t *testing.T) {
	h := newTokHarness(t, false)
	h.login(credentials{Registry: "https://other.example", Login: "alice", Token: "tok"})
	code, _, errb := h.run("logout")
	if code != 0 || !strings.Contains(errb, "not logged in") || !h.hasCreds() {
		t.Fatalf("exit %d stderr %q hasCreds %v", code, errb, h.hasCreds())
	}
}

func TestLogoutServerTroubleStillLogsOutLocally(t *testing.T) {
	for name, status := range map[string]int{"500": 500, "502": 502, "429": 429} {
		h := newTokHarness(t, true)
		h.s.set(status, `{"error":"boom"}`)
		code, _, errb := h.run("logout")
		if code != 0 || h.hasCreds() {
			t.Errorf("%s: exit %d hasCreds %v", name, code, h.hasCreds())
		}
		if !strings.Contains(errb, "may remain valid until it expires") {
			t.Errorf("%s: stderr %q", name, errb)
		}
	}
}

func TestLogoutServerUnreachable(t *testing.T) {
	h := newTokHarness(t, true)
	h.s.srv.Close()
	code, _, errb := h.run("logout")
	if code != 0 || h.hasCreds() || !strings.Contains(errb, "may remain valid until it expires") {
		t.Fatalf("exit %d hasCreds %v stderr %q", code, h.hasCreds(), errb)
	}
}

func TestLogoutAlreadyInvalidToken(t *testing.T) {
	h := newTokHarness(t, true)
	h.s.set(401, `{"error":"authentication required"}`)
	code, _, errb := h.run("logout")
	if code != 0 || h.hasCreds() {
		t.Fatalf("exit %d hasCreds %v", code, h.hasCreds())
	}
	if strings.Contains(errb, "may remain valid") {
		t.Errorf("a 401 means the token is already dead: %q", errb)
	}
}

func TestLogoutOlderServer(t *testing.T) {
	h := newTokHarness(t, true)
	h.s.set(404, "404 page not found\n")
	code, _, errb := h.run("logout")
	if code != 0 || h.hasCreds() {
		t.Fatalf("exit %d hasCreds %v", code, h.hasCreds())
	}
	if !strings.Contains(errb, "does not support token management") || !strings.Contains(errb, "may remain valid until it expires") {
		t.Errorf("stderr %q", errb)
	}
	if strings.Contains(errb, "registry error") {
		t.Errorf("raw error leaked: %q", errb)
	}
}

func TestLogoutUsage(t *testing.T) {
	h := newTokHarness(t, true)
	if code, _, errb := h.run("logout", "extra"); code != 2 || !strings.Contains(errb, "usage: capm logout") {
		t.Fatalf("exit %d %q", code, errb)
	}
	if !h.hasCreds() {
		t.Fatal("credentials removed on a usage error")
	}
}

const tokenListJSON = `[
 {"id":3,"name":"laptop","createdAt":"2026-11-01T10:00:00Z","lastUsedAt":"2026-11-10T08:30:00Z","expiresAt":"2027-01-30T10:00:00Z","current":true},
 {"id":9,"name":"","createdAt":"2026-10-02T23:59:59Z","expiresAt":"2027-01-01T00:00:00Z","current":false},
 {"id":12,"name":"ci\u001b[2J\nbox","createdAt":"2026-09-01T00:00:00Z","lastUsedAt":"2026-09-02T00:00:00Z","current":false}
]`

func TestTokensTable(t *testing.T) {
	h := newTokHarness(t, true)
	h.s.set(200, tokenListJSON)
	code, out, errb := h.run("tokens")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if r := h.s.requests(); len(r) != 1 || r[0].method != "GET" || r[0].path != "/v1/auth/tokens" || r[0].auth != "Bearer tok-123" {
		t.Fatalf("%+v", r)
	}
	if strings.Contains(out, "\x1b") {
		t.Fatalf("unsanitised output %q", out)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 4 {
		t.Fatalf("lines: %q", lines)
	}
	want := [][]string{
		{"", "ID", "NAME", "CREATED", "LAST USED", "EXPIRES"},
		{"*", "3", "laptop", "2026-11-01", "2026-11-10", "2027-01-30"},
		{"", "9", "-", "2026-10-02", "-", "2027-01-01"},
		{"", "12", "ci[2Jbox", "2026-09-01", "2026-09-02", "never"},
	}
	for i, l := range lines {
		got := strings.Fields(l)
		if strings.Join(got, " ") != strings.Join(strings.Fields(strings.Join(want[i], " ")), " ") {
			t.Errorf("line %d: %q, want %v", i, l, want[i])
		}
	}
	if !strings.HasPrefix(lines[1], "*") || strings.HasPrefix(lines[2], "*") {
		t.Errorf("current marker wrong: %q", lines)
	}
}

func TestTokensErrors(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
		want   string
	}{
		"older server": {404, "404 page not found\n", "does not support token management"},
		"401":          {401, `{"error":"authentication required"}`, "run capm login"},
		"500":          {500, `{"error":"internal error"}`, "internal error"},
	}
	for name, c := range cases {
		h := newTokHarness(t, true)
		h.s.set(c.status, c.body)
		code, out, errb := h.run("tokens")
		if code != 1 || out != "" || !strings.Contains(errb, c.want) {
			t.Errorf("%s: exit %d out %q err %q", name, code, out, errb)
		}
		if name == "older server" && strings.Contains(errb, "registry error") {
			t.Errorf("raw error leaked: %q", errb)
		}
	}
	h := newTokHarness(t, false)
	if code, _, errb := h.run("tokens"); code != 1 || !strings.Contains(errb, "run capm login") {
		t.Errorf("not logged in: %d %q", code, errb)
	}
	if len(h.s.requests()) != 0 {
		t.Error("request made while logged out")
	}
}

func TestTokensRevoke(t *testing.T) {
	h := newTokHarness(t, true)
	h.s.set(200, tokenListJSON)
	// The server replies to every request alike, so use a router instead.
	var mu sync.Mutex
	var reqs []tokReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqs = append(reqs, tokReq{method: r.Method, path: r.URL.Path})
		mu.Unlock()
		if r.Method == "GET" {
			io.WriteString(w, tokenListJSON)
			return
		}
		if r.URL.Path == "/v1/auth/tokens/404" {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":"not found"}`)
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	h.env.registry = srv.URL
	h.login(credentials{Registry: srv.URL, Login: "alice", Token: "tok-123"})

	if code, out, errb := h.run("tokens", "revoke", "9"); code != 0 || !strings.Contains(out, "Revoked token 9") {
		t.Fatalf("exit %d out %q err %q", code, out, errb)
	}
	if !h.hasCreds() {
		t.Fatal("revoking another token must keep the credentials")
	}
	if last := reqs[len(reqs)-1]; last.method != "DELETE" || last.path != "/v1/auth/tokens/9" {
		t.Fatalf("%+v", reqs)
	}
	// Current token: server-side revoke, then local credentials go too.
	if code, out, errb := h.run("tokens", "revoke", "3"); code != 0 || !strings.Contains(out, "Revoked token 3") {
		t.Fatalf("exit %d out %q err %q", code, out, errb)
	}
	if h.hasCreds() {
		t.Fatal("revoking the current token must delete local credentials")
	}
	// An id the list does not contain is reported without a DELETE.
	h.login(credentials{Registry: srv.URL, Login: "alice", Token: "tok-123"})
	before := len(reqs)
	if code, _, errb := h.run("tokens", "revoke", "77"); code != 1 || !strings.Contains(errb, "no token with id 77") {
		t.Fatalf("exit %d err %q", code, errb)
	}
	for _, r := range reqs[before:] {
		if r.method == "DELETE" {
			t.Fatalf("DELETE sent for an unlisted id: %+v", r)
		}
	}
}

func TestTokensRevokeUsage(t *testing.T) {
	h := newTokHarness(t, true)
	for _, args := range [][]string{
		{"tokens", "revoke"}, {"tokens", "revoke", "abc"}, {"tokens", "revoke", "0"},
		{"tokens", "revoke", "-4"}, {"tokens", "revoke", "1", "2"}, {"tokens", "bogus"}, {"tokens", "x", "y"},
	} {
		if code, _, errb := h.run(args...); code != 2 || !strings.Contains(errb, "usage:") {
			t.Errorf("%v: exit %d %q", args, code, errb)
		}
	}
	if len(h.s.requests()) != 0 {
		t.Error("requests made for bad usage")
	}
}

func TestTokensRevokeOlderServer(t *testing.T) {
	h := newTokHarness(t, true)
	h.s.set(404, "404 page not found\n")
	code, _, errb := h.run("tokens", "revoke", "4")
	if code != 1 || !strings.Contains(errb, "does not support token management") {
		t.Fatalf("exit %d %q", code, errb)
	}
}

func TestExpiryWarning(t *testing.T) {
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	cases := []struct {
		name string
		exp  string
		want string
	}{
		{"none", "", ""},
		{"garbage", "soon", ""},
		{"far", now.Add(30 * day).Format(time.RFC3339), ""},
		{"exactly 7 days", now.Add(7 * day).Format(time.RFC3339), ""},
		{"just under 7", now.Add(7*day - time.Minute).Format(time.RFC3339), "your capm token expires in 7 days; run capm login\n"},
		{"3 days", now.Add(3 * day).Format(time.RFC3339), "your capm token expires in 3 days; run capm login\n"},
		{"3 days and a bit", now.Add(3*day + time.Hour).Format(time.RFC3339), "your capm token expires in 4 days; run capm login\n"},
		{"hours", now.Add(5 * time.Hour).Format(time.RFC3339), "your capm token expires in 1 day; run capm login\n"},
		{"already expired", now.Add(-time.Hour).Format(time.RFC3339), ""},
	}
	for _, c := range cases {
		if got := expiryWarning(credentials{ExpiresAt: c.exp}, now); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestOlderCredentialsFileWithoutExpiry(t *testing.T) {
	h := newTokHarness(t, false)
	os.MkdirAll(h.env.credDir, 0o700)
	os.WriteFile(h.cred, []byte(`{"registry":"`+h.env.registry+`","login":"alice","token":"tok-123"}`), 0o600)
	c, err := loadCreds(h.env)
	if err != nil || c.ExpiresAt != "" || c.Token != "tok-123" {
		t.Fatalf("%+v %v", c, err)
	}
}

func TestAuthenticatedCommandsWarnOnStderrAfterOutput(t *testing.T) {
	h := newTokHarness(t, false)
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	h.env.now = func() time.Time { return now }
	h.login(credentials{Registry: h.env.registry, Login: "alice", Token: "tok-123",
		ExpiresAt: now.Add(2 * 24 * time.Hour).Format(time.RFC3339)})
	const warn = "your capm token expires in 2 days; run capm login\n"

	h.s.set(200, tokenListJSON)
	if code, out, errb := h.run("tokens"); code != 0 || errb != warn || strings.Contains(out, "capm login") {
		t.Fatalf("tokens: %d out %q err %q", code, out, errb)
	}
	h.s.set(200, `[]`)
	if code, _, errb := h.run("admin", "log"); code != 0 || !strings.HasSuffix(errb, warn) {
		t.Fatalf("admin: %d err %q", code, errb)
	}
	// Failed commands warn too (the token may be why they failed), exactly once.
	if _, _, errb := h.run("push", t.TempDir()); strings.Count(errb, warn) != 1 {
		t.Fatalf("push: err %q", errb)
	}
	// Logout is about to delete the token: no warning.
	h.s.set(204, "")
	if code, _, errb := h.run("logout"); code != 0 || strings.Contains(errb, "expires in") {
		t.Fatalf("logout: %d %q", code, errb)
	}
	// Anonymous commands never read credentials and never warn.
	h.login(credentials{Registry: h.env.registry, Login: "alice", Token: "tok-123",
		ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339)})
	h.s.set(200, `[]`)
	if _, _, errb := h.run("list"); strings.Contains(errb, "expires in") {
		t.Fatalf("list warned: %q", errb)
	}
}

func TestLoginSendsHostnameAndSavesExpiry(t *testing.T) {
	var gotName string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/device":
			io.WriteString(w, `{"device_code":"dc","user_code":"AB-12","verification_uri":"https://example.test/d","interval":1,"expires_in":60}`)
		case "/v1/auth/token":
			var in struct{ Name string }
			json.NewDecoder(r.Body).Decode(&in)
			mu.Lock()
			gotName = in.Name
			mu.Unlock()
			io.WriteString(w, `{"token":"newtok"}`)
		case "/v1/auth/me":
			io.WriteString(w, `{"id":1,"login":"alice","tokenId":5,"tokenExpiresAt":"2027-02-09T10:00:00Z"}`)
		}
	}))
	defer srv.Close()
	for host, want := range map[string]string{"dev-box": "dev-box"} {
		e := env{registry: srv.URL, credDir: filepath.Join(t.TempDir(), "capm"), sleep: func(time.Duration) {},
			hostname: func() (string, error) { return host, nil }}
		var out, errb bytes.Buffer
		if code := runEnv([]string{"login"}, &out, &errb, e); code != 0 {
			t.Fatalf("exit %d %s", code, errb.String())
		}
		if gotName != want {
			t.Errorf("name %q, want %q", gotName, want)
		}
		c, err := loadCreds(e)
		if err != nil || c.ExpiresAt != "2027-02-09T10:00:00Z" {
			t.Errorf("%+v %v", c, err)
		}
	}
	// A hostname error is not fatal; the name is simply empty.
	e := env{registry: srv.URL, credDir: filepath.Join(t.TempDir(), "capm"), sleep: func(time.Duration) {},
		hostname: func() (string, error) { return "", errors.New("no hostname") }}
	var out, errb bytes.Buffer
	if code := runEnv([]string{"login"}, &out, &errb, e); code != 0 || gotName != "" {
		t.Fatalf("exit %d name %q", code, gotName)
	}
}

func TestAdminRevokeTokens(t *testing.T) {
	a, run := adminHarness(t)
	a.reply = `{"id":42,"revoked":3}`
	code, out, errb := run("revoke-tokens", "bob")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if r := a.reqs[0]; r.method != "DELETE" || r.path != "/v1/admin/users/bob/tokens" || r.auth != "Bearer tok-123" {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(out, "Revoked 3 token(s) for bob") {
		t.Errorf("stdout %q", out)
	}
	if code, _, _ := run("revoke-tokens", "12345"); code != 0 || a.reqs[1].path != "/v1/admin/users/12345/tokens" {
		t.Fatalf("by id: %+v", a.reqs)
	}
	for _, args := range [][]string{{"revoke-tokens"}, {"revoke-tokens", "a", "b"}, {"revoke-tokens", "bob", "--reason", "x"}} {
		if code, _, _ := run(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	a.status = 404
	a.reply = `{"error":"not found"}`
	if code, _, errb := run("revoke-tokens", "ghost"); code != 1 || !strings.Contains(errb, "not found") {
		t.Errorf("404: %d %q", code, errb)
	}
}

func TestMainUsageListsLogoutAndTokens(t *testing.T) {
	var out, errb bytes.Buffer
	runEnv([]string{"help"}, &out, &errb, env{})
	for _, w := range []string{"logout", "tokens"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("usage lacks %q", w)
		}
	}
}
