package main

import (
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
)

// goneServer answers every bundle request with 410 and a reason, like a
// registry where the version was removed. It counts download calls.
func goneServer(t *testing.T, reason string) (*httptest.Server, *int) {
	t.Helper()
	var mu sync.Mutex
	downloads := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/download") {
			mu.Lock()
			downloads++
			mu.Unlock()
		}
		w.WriteHeader(410)
		json.NewEncoder(w).Encode(map[string]any{"error": "removed by the registry: " + reason, "reason": reason, "removed": true})
	}))
	t.Cleanup(srv.Close)
	return srv, &downloads
}

func TestRemovedVersionReportedByPullInspectRun(t *testing.T) {
	const reason = "contains malware\x1b[2J and\nmore"
	srv, downloads := goneServer(t, reason)
	chdirTemp(t)
	cases := map[string][]string{
		"pull":    {"pull", "bob/agent@1.0.0"},
		"inspect": {"inspect", "bob/agent@1.0.0"},
		"run":     {"run", "--yes", "--allow-unenforced-egress", "--model-url", "http://127.0.0.1:1", "bob/agent@1.0.0"},
		"latest":  {"pull", "bob/agent"},
	}
	for name, args := range cases {
		var out, errb bytes.Buffer
		code := runEnv(args, &out, &errb, env{registry: srv.URL})
		if code != 1 {
			t.Errorf("%s: exit %d, want 1 (stderr %q)", name, code, errb.String())
		}
		if !strings.Contains(errb.String(), "removed by the registry: contains malware") {
			t.Errorf("%s: stderr lacks the reason: %q", name, errb.String())
		}
		if strings.Contains(errb.String(), "registry error") || strings.Contains(errb.String(), "410") {
			t.Errorf("%s: a 410 must not read as a generic HTTP error: %q", name, errb.String())
		}
		if strings.Contains(errb.String(), "\x1b") || strings.Count(errb.String(), "\n") != 1 {
			t.Errorf("%s: reason not sanitised: %q", name, errb.String())
		}
		if out.Len() != 0 {
			t.Errorf("%s: unexpected stdout %q", name, out.String())
		}
	}
	if *downloads != 0 {
		t.Errorf("downloaded %d times", *downloads)
	}
	if ents, _ := os.ReadDir("."); len(ents) != 0 {
		t.Errorf("cwd not clean: %v", ents)
	}
}

type adminReq struct {
	method, path, auth, body string
}

// adminServer records admin requests and replies with a canned status/body.
type adminServer struct {
	srv    *httptest.Server
	mu     sync.Mutex
	reqs   []adminReq
	status int
	reply  string
}

func newAdminServer(t *testing.T) *adminServer {
	a := &adminServer{status: 200, reply: `{}`}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		a.mu.Lock()
		a.reqs = append(a.reqs, adminReq{r.Method, r.URL.RequestURI(), r.Header.Get("Authorization"), string(b)})
		st, rp := a.status, a.reply
		a.mu.Unlock()
		w.WriteHeader(st)
		io.WriteString(w, rp)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

// adminHarness has stored credentials so admin commands are authenticated.
func adminHarness(t *testing.T) (*adminServer, func(args ...string) (int, string, string)) {
	t.Helper()
	a := newAdminServer(t)
	e := env{registry: a.srv.URL, credDir: filepath.Join(t.TempDir(), "capm")}
	if err := saveCreds(e, credentials{Registry: e.registry, Login: "root", Token: "tok-123"}); err != nil {
		t.Fatal(err)
	}
	return a, func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := runEnv(append([]string{"admin"}, args...), &out, &errb, e)
		return code, out.String(), errb.String()
	}
}

func TestAdminRemoveSendsRightRequest(t *testing.T) {
	a, run := adminHarness(t)
	a.reply = `{"removed":true,"versions":["1.0.0"],"blobsDeleted":1}`
	code, out, errb := run("remove", "bob/agent@1.0.0", "--reason", "contains malware")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	r := a.reqs[0]
	if r.method != "POST" || r.path != "/v1/admin/bundles/bob/agent/1.0.0/remove" || r.auth != "Bearer tok-123" {
		t.Fatalf("%+v", r)
	}
	var body map[string]string
	json.Unmarshal([]byte(r.body), &body)
	if body["reason"] != "contains malware" {
		t.Fatalf("body %q", r.body)
	}
	if !strings.Contains(out, "bob/agent@1.0.0") {
		t.Errorf("stdout %q", out)
	}
	// Whole bundle, reason first, = form.
	if code, _, errb := run("remove", "--reason=spam", "bob/agent"); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if r := a.reqs[1]; r.method != "POST" || r.path != "/v1/admin/bundles/bob/agent/remove" {
		t.Fatalf("%+v", r)
	}
}

func TestAdminRestoreUnbanBanLog(t *testing.T) {
	a, run := adminHarness(t)
	if code, _, e := run("restore", "bob/agent@1.0.0"); code != 0 {
		t.Fatalf("%d %s", code, e)
	}
	if r := a.reqs[0]; r.method != "DELETE" || r.path != "/v1/admin/bundles/bob/agent/1.0.0/remove" {
		t.Fatalf("%+v", r)
	}
	if code, _, e := run("restore", "bob/agent"); code != 0 {
		t.Fatalf("%d %s", code, e)
	}
	if r := a.reqs[1]; r.method != "DELETE" || r.path != "/v1/admin/bundles/bob/agent/remove" {
		t.Fatalf("%+v", r)
	}
	if code, _, e := run("ban", "bob", "--reason", "spam"); code != 0 {
		t.Fatalf("%d %s", code, e)
	}
	if r := a.reqs[2]; r.method != "POST" || r.path != "/v1/admin/users/bob/ban" || !strings.Contains(r.body, `"spam"`) {
		t.Fatalf("%+v", r)
	}
	if code, _, e := run("ban", "12345", "--reason", "spam"); code != 0 {
		t.Fatalf("%d %s", code, e)
	}
	if r := a.reqs[3]; r.path != "/v1/admin/users/12345/ban" {
		t.Fatalf("%+v", r)
	}
	if code, _, e := run("unban", "bob"); code != 0 {
		t.Fatalf("%d %s", code, e)
	}
	if r := a.reqs[4]; r.method != "DELETE" || r.path != "/v1/admin/users/bob/ban" {
		t.Fatalf("%+v", r)
	}
	a.reply = `[{"id":2,"adminId":1,"admin":"root","action":"ban_user","target":"user:5","reason":"spam\u001b[2J","createdAt":"2026-11-11T10:00:00Z"}]`
	code, out, e := run("log")
	if code != 0 {
		t.Fatalf("%d %s", code, e)
	}
	if r := a.reqs[5]; r.method != "GET" || !strings.HasPrefix(r.path, "/v1/admin/log") {
		t.Fatalf("%+v", r)
	}
	if !strings.Contains(out, "ban_user") || !strings.Contains(out, "user:5") || strings.Contains(out, "\x1b") {
		t.Errorf("log output %q", out)
	}
}

func TestAdminReasonRequired(t *testing.T) {
	a, run := adminHarness(t)
	for _, args := range [][]string{
		{"remove", "bob/agent@1.0.0"},
		{"remove", "bob/agent", "--reason", "  "},
		{"ban", "bob"},
		{"remove", "--reason", "x"},
		{"remove", "bad ref", "--reason", "x"},
		{"remove", "bob/agent@latest", "--reason", "x"},
		{"remove", "bob/agent", "--bogus", "--reason", "x"},
		{"restore"},
		{"unban"},
		{"log", "extra"},
	} {
		if code, _, e := run(args...); code != 2 || e == "" {
			t.Errorf("%v: exit %d stderr %q, want 2 with a message", args, code, e)
		}
	}
	if len(a.reqs) != 0 {
		t.Fatalf("invalid invocations must send nothing: %+v", a.reqs)
	}
}

func TestAdminNoSubcommandPrintsUsageAndIsHiddenFromMain(t *testing.T) {
	var out, errb bytes.Buffer
	if code := runEnv([]string{"admin"}, &out, &errb, env{registry: "http://127.0.0.1:1"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	for _, w := range []string{"remove", "restore", "ban", "unban", "log", "--reason"} {
		if !strings.Contains(out.String(), w) {
			t.Errorf("admin usage lacks %q:\n%s", w, out.String())
		}
	}
	out.Reset()
	runEnv([]string{"help"}, &out, &errb, env{})
	if strings.Contains(out.String(), "admin") {
		t.Errorf("main usage must not mention admin:\n%s", out.String())
	}
	if code := runEnv([]string{"admin", "frobnicate"}, &out, &errb, env{}); code != 2 {
		t.Errorf("unknown subcommand exit %d", code)
	}
}

func TestAdminNotLoggedIn(t *testing.T) {
	var out, errb bytes.Buffer
	e := env{registry: "http://127.0.0.1:1", credDir: t.TempDir()}
	if code := runEnv([]string{"admin", "log"}, &out, &errb, e); code != 1 || !strings.Contains(errb.String(), "capm login") {
		t.Fatalf("%d %q", code, errb.String())
	}
}

func TestAdminNonAdminSeesPlainNotFound(t *testing.T) {
	a, run := adminHarness(t)
	a.status, a.reply = 404, "404 page not found\n"
	for _, args := range [][]string{
		{"remove", "bob/agent", "--reason", "x"},
		{"restore", "bob/agent"},
		{"ban", "bob", "--reason", "x"},
		{"unban", "bob"},
		{"log"},
	} {
		code, out, e := run(args...)
		if code != 1 || out != "" || !strings.Contains(e, "not found (are you an admin on this registry?)") {
			t.Errorf("%v: %d %q %q", args, code, out, e)
		}
		if strings.Contains(e, "404") || strings.Contains(e, "registry error") {
			t.Errorf("%v: should be plain: %q", args, e)
		}
	}
}

func TestAdminConflictShowsServerMessageSanitised(t *testing.T) {
	a, run := adminHarness(t)
	msg, _ := json.Marshal(map[string]string{"error": "cannot restore: data deleted\x1b[2J"})
	a.status, a.reply = 409, string(msg)
	code, _, e := run("restore", "bob/agent@1.0.0")
	if code != 1 || !strings.Contains(e, "cannot restore: data deleted") || strings.Contains(e, "\x1b") {
		t.Fatalf("%d %q", code, e)
	}
}
