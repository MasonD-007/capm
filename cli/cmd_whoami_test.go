package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// whoamiServer answers every request with status and body, and counts them.
func whoamiServer(t *testing.T, status int, body string) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func runWhoami(e env, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := runEnv(append([]string{"whoami"}, args...), &out, &errb, e)
	return code, out.String(), errb.String()
}

func loggedInEnv(t *testing.T, registry string) env {
	t.Helper()
	e := env{registry: registry, credDir: t.TempDir()}
	if err := saveCreds(e, credentials{Registry: registry, Login: "alice", Token: "tok"}); err != nil {
		t.Fatal(err)
	}
	return e
}

func TestWhoamiNotLoggedInMakesNoRequest(t *testing.T) {
	srv, n := whoamiServer(t, 200, `{}`)
	code, out, errs := runWhoami(env{registry: srv.URL, credDir: t.TempDir()})
	want := "capm whoami: not logged in to " + srv.URL + "; run capm login\n"
	if code != 1 || out != "" || errs != want {
		t.Errorf("code %d out %q err %q", code, out, errs)
	}
	if n.Load() != 0 {
		t.Errorf("%d requests, want 0", n.Load())
	}
}

func TestWhoamiPrintsOnlyLoginOnStdout(t *testing.T) {
	srv, _ := whoamiServer(t, 200, `{"id":42,"login":"alice"}`)
	code, out, errs := runWhoami(loggedInEnv(t, srv.URL))
	if code != 0 || out != "alice\n" {
		t.Errorf("code %d out %q", code, out)
	}
	if want := "logged in to " + srv.URL + " as alice (GitHub ID 42)\n"; errs != want {
		t.Errorf("err %q, want %q", errs, want)
	}
}

func TestWhoamiExpiredToken(t *testing.T) {
	srv, _ := whoamiServer(t, 401, `{"error":"invalid token"}`)
	code, out, errs := runWhoami(loggedInEnv(t, srv.URL))
	if want := "capm whoami: the stored token is no longer valid; run capm login\n"; code != 1 || out != "" || errs != want {
		t.Errorf("code %d out %q err %q", code, out, errs)
	}
}

func TestWhoamiOtherServerError(t *testing.T) {
	srv, _ := whoamiServer(t, 500, `{"error":"boom"}`)
	code, out, errs := runWhoami(loggedInEnv(t, srv.URL))
	if code != 1 || out != "" || !strings.HasPrefix(errs, "capm whoami: ") || !strings.Contains(errs, "boom") {
		t.Errorf("code %d out %q err %q", code, out, errs)
	}
}

func TestWhoamiUsage(t *testing.T) {
	srv, n := whoamiServer(t, 200, `{}`)
	code, out, errs := runWhoami(loggedInEnv(t, srv.URL), "extra")
	if code != 2 || out != "" || errs != "usage: capm whoami\n" || n.Load() != 0 {
		t.Errorf("code %d out %q err %q requests %d", code, out, errs, n.Load())
	}
}

func TestWhoamiSanitisesLogin(t *testing.T) {
	srv, _ := whoamiServer(t, 200, `{"id":1,"login":"al\u001b[31mi‮ce"}`)
	code, out, errs := runWhoami(loggedInEnv(t, srv.URL))
	if code != 0 || out != "al[31mice\n" {
		t.Errorf("code %d out %q", code, out)
	}
	for _, bad := range []string{"\x1b", "‮"} {
		if strings.Contains(out+errs, bad) {
			t.Errorf("%q reached the terminal: %q %q", bad, out, errs)
		}
	}
}

func TestUsageListsWhoami(t *testing.T) {
	if !strings.Contains(usage, "\n  whoami") {
		t.Error("usage lacks whoami")
	}
}
