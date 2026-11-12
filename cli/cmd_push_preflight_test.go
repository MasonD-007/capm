package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// countingHarness logs in against a server that records every request.
func countingHarness(t *testing.T) (*harness, *atomic.Int32) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(201)
		w.Write([]byte("{}"))
	}))
	t.Cleanup(srv.Close)
	h := newHarness(t)
	h.env.registry = srv.URL
	if err := saveCreds(h.env, credentials{Registry: srv.URL, Login: "alice", Token: "tok"}); err != nil {
		t.Fatal(err)
	}
	return h, &hits
}

func TestPushRefusesSecretFileBeforeAnyRequest(t *testing.T) {
	h, hits := countingHarness(t)
	dir := lintBundle(t, map[string]string{"capm.yaml": lintManifest("a", "1.0.0", "cfg/.env"), "cfg/.env": "T=" + fakeGH + "\n"})
	if code := h.run("push", dir); code != 1 {
		t.Fatalf("exit %d", code)
	}
	s := h.errb.String()
	if !strings.Contains(s, "error[secret_file]: cfg/.env") || !strings.Contains(s, "--allow-secret-files") {
		t.Errorf("stderr:\n%s", s)
	}
	if strings.Contains(s+h.out.String(), fakeGH) {
		t.Error("token leaked")
	}
	if hits.Load() != 0 {
		t.Errorf("%d requests were made", hits.Load())
	}
	if h.out.Len() != 0 {
		t.Errorf("stdout %q", h.out.String())
	}
}

func TestPushRefusesMissingContextBeforeAnyRequest(t *testing.T) {
	h, hits := countingHarness(t)
	dir := lintBundle(t, map[string]string{"capm.yaml": lintManifest("a", "1.0.0", "nope.md")})
	if code := h.run("push", dir); code != 1 || hits.Load() != 0 {
		t.Fatalf("exit %d hits %d", code, hits.Load())
	}
	if !strings.Contains(h.errb.String(), "error[context_missing]") {
		t.Errorf("stderr %q", h.errb.String())
	}
	// --allow-secret-files does not excuse a missing file.
	if code := h.run("push", "--allow-secret-files", dir); code != 1 || hits.Load() != 0 {
		t.Fatalf("allow flag: exit %d hits %d", code, hits.Load())
	}
}

func TestPushAllowSecretFilesDowngrades(t *testing.T) {
	h := newHarness(t)
	h.mustLogin(t)
	dir := lintBundle(t, map[string]string{"capm.yaml": lintManifest("a", "1.0.0", "cfg/.env"), "cfg/.env": "T=" + fakeGH + "\n"})
	if code := h.run("push", dir, "--allow-secret-files"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	s := h.errb.String()
	if !strings.Contains(s, "warning[secret_file]: cfg/.env") || strings.Contains(s, "error[") {
		t.Errorf("stderr:\n%s", s)
	}
	if strings.Contains(s, fakeGH) {
		t.Error("token leaked")
	}
	if h.reg.pushBody == nil {
		t.Error("nothing pushed")
	}
}

func TestPushRunsOnlyErrorLevelChecks(t *testing.T) {
	h := newHarness(t)
	h.mustLogin(t)
	// No description, an unlisted file and a nearby .env: all warning-level,
	// so push stays quiet about them.
	dir := lintBundle(t, map[string]string{"capm.yaml": strings.Replace(lintManifest("a", "1.0.0", ""), "  description: A test bundle.\n", "", 1),
		"extra.md": "x", ".env": "A=1"})
	if code := h.run("push", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if strings.Contains(h.errb.String(), "warning[") || strings.Contains(h.errb.String(), "error[") {
		t.Errorf("push printed lint output: %q", h.errb.String())
	}
}

func TestPushRefusalWithUnroutableRegistry(t *testing.T) {
	h := newHarness(t)
	h.env.registry = "http://127.0.0.1:1"
	saveCreds(h.env, credentials{Registry: h.env.registry, Login: "alice", Token: "tok"})
	dir := lintBundle(t, map[string]string{"capm.yaml": lintManifest("a", "1.0.0", ".env"), ".env": "x"})
	if code := h.run("push", dir); code != 1 || strings.Contains(h.errb.String(), "connect") {
		t.Errorf("exit %d %q", code, h.errb.String())
	}
}

func TestPushFlagUsage(t *testing.T) {
	h := newHarness(t)
	h.mustLogin(t)
	for _, args := range [][]string{{"push", "--allow-secret-files"}, {"push", "--bogus", "x"}, {"push", "a", "b"}} {
		if code := h.run(args...); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}
