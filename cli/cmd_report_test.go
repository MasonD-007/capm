package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// reportHarness serves one canned reply and records the request. loggedIn
// stores credentials first.
func reportHarness(t *testing.T, status int, reply string, loggedIn bool) (*adminServer, func(args ...string) (int, string, string)) {
	t.Helper()
	a := newAdminServer(t)
	a.status, a.reply = status, reply
	e := env{registry: a.srv.URL, credDir: filepath.Join(t.TempDir(), "capm")}
	if loggedIn {
		if err := saveCreds(e, credentials{Registry: e.registry, Login: "me", Token: "tok-9"}); err != nil {
			t.Fatal(err)
		}
	}
	return a, func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := runEnv(append([]string{"report"}, args...), &out, &errb, e)
		return code, out.String(), errb.String()
	}
}

func TestReportSendsRequestAnonymously(t *testing.T) {
	a, run := reportHarness(t, 202, `{}`, false)
	code, out, errb := run("bob/agent@1.2.0", "--reason", "malware", "--details", "steals keys")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	r := a.reqs[0]
	if r.method != "POST" || r.path != "/v1/bundles/bob/agent/report" || r.auth != "" {
		t.Fatalf("%+v", r)
	}
	var body map[string]string
	json.Unmarshal([]byte(r.body), &body)
	if body["version"] != "1.2.0" || body["reason"] != "malware" || body["details"] != "steals keys" || len(body) != 3 {
		t.Fatalf("body %q", r.body)
	}
	if !strings.Contains(out, "Thanks") || strings.Contains(out, "(report") {
		t.Fatalf("stdout %q", out)
	}
}

func TestReportSendsStoredTokenAndWholeBundle(t *testing.T) {
	a, run := reportHarness(t, 202, `{}`, true)
	if code, _, errb := run("--reason=other", "bob/agent", "--details=odd behaviour"); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	r := a.reqs[0]
	var body map[string]string
	json.Unmarshal([]byte(r.body), &body)
	if r.auth != "Bearer tok-9" || body["version"] != "" {
		t.Fatalf("%+v", r)
	}
}

func TestReportValidatesLocallyBeforeAnyRequest(t *testing.T) {
	a, run := reportHarness(t, 202, `{}`, false)
	bad := [][]string{
		{},
		{"bob/agent"},
		{"bob/agent", "--reason", "spam"},
		{"bob/agent", "--reason", "other"},
		{"bob/agent", "--reason", "other", "--details", "  "},
		{"bob/agent", "--reason", "malware", "--details", strings.Repeat("x", 2001)},
		{"bob/agent@latest", "--reason", "malware"},
		{"nonsense", "--reason", "malware"},
		{"bob/agent", "--reason", "malware", "--bogus"},
		{"bob/agent", "extra/arg", "--reason", "malware"},
		{"bob/agent", "--reason"},
	}
	for _, args := range bad {
		if code, _, _ := run(args...); code != 2 {
			t.Errorf("%v: exit %d, want 2", args, code)
		}
	}
	if len(a.reqs) != 0 {
		t.Fatalf("%d requests made for invalid input", len(a.reqs))
	}
}

func TestReportServerAnswers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		reply  string
		want   string
	}{
		{"id returned is not required", 201, `{"id": 7}`, "Thanks"},
		{"rate limit", 429, `{"error":"rate limit exceeded; retry later"}`, "too many reports from your network"},
		{"validation", 400, `{"error":"version: this bundle has no such version"}`, "no such version"},
		{"unknown bundle", 404, `{"error":"bundle not found"}`, "bundle not found"},
		{"route unknown or disabled", 404, `{"error":"not found"}`, "does not accept reports"},
		{"older server", 404, `404 page not found`, "does not accept reports"},
		{"too large", 413, `{"error":"report too large"}`, "report too large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, run := reportHarness(t, tc.status, tc.reply, false)
			code, out, errb := run("bob/agent", "--reason", "malware")
			if tc.status/100 == 2 {
				if code != 0 || !strings.Contains(out, tc.want) {
					t.Fatalf("%d %q %q", code, out, errb)
				}
				return
			}
			if code != 1 || !strings.Contains(errb, tc.want) || out != "" {
				t.Fatalf("%d out=%q err=%q", code, out, errb)
			}
		})
	}
}

func TestReportOlderServerMessageIsHonest(t *testing.T) {
	_, run := reportHarness(t, 404, `404 page not found`, false)
	_, _, errb := run("bob/agent", "--reason", "malware")
	// A 404 for an existing bundle cannot be told from a missing bundle on an
	// old server, so the message must not claim either.
	for _, must := range []string{"older registry", "switched off", "bob/agent"} {
		if !strings.Contains(errb, must) {
			t.Errorf("message lacks %q: %q", must, errb)
		}
	}
}

func TestReportSanitisesServerText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte("{\"error\":\"bad\\u001b[2J\\nthing\"}"))
	}))
	defer srv.Close()
	var out, errb bytes.Buffer
	runEnv([]string{"report", "bob/agent", "--reason", "malware"}, &out, &errb, env{registry: srv.URL, credDir: t.TempDir()})
	if strings.Contains(errb.String(), "\x1b") || strings.Count(errb.String(), "\n") != 1 {
		t.Fatalf("%q", errb.String())
	}
}
