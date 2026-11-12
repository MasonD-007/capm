package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseSize(t *testing.T) {
	ok := map[string]int64{
		"0": 0, "1": 1, "524288000": 524288000, "500MiB": 500 << 20, "2GiB": 2 << 30, "2gib": 2 << 30,
		"10KiB": 10 << 10, "1TiB": 1 << 40, "7B": 7, "1MB": 1_000_000, "3GB": 3_000_000_000, "5KB": 5000,
		" 100MiB ": 100 << 20, "100 MiB": 100 << 20, "1M": 1 << 20, "2G": 2 << 30,
	}
	for in, want := range ok {
		if got, err := parseSize(in); err != nil || got != want {
			t.Errorf("parseSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "-1", "-5MiB", "abc", "1.5GiB", "MiB", "5 parsecs", "99999999999999TiB", "9223372036854775807", "1e3", "0x10"} {
		if got, err := parseSize(in); err == nil {
			t.Errorf("parseSize(%q) = %d, want an error", in, got)
		}
	}
}

func TestHumanBytes(t *testing.T) {
	for in, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 100 << 20: "100.0 MiB", 3 << 30: "3.0 GiB", 1536: "1.5 KiB"} {
		if got := humanBytes(in); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}

func usageHarness(t *testing.T, loggedIn bool) (*adminServer, func(args ...string) (int, string, string)) {
	t.Helper()
	a := newAdminServer(t)
	e := env{registry: a.srv.URL, credDir: filepath.Join(t.TempDir(), "capm")}
	if loggedIn {
		if err := saveCreds(e, credentials{Registry: e.registry, Login: "alice", Token: "tok-123"}); err != nil {
			t.Fatal(err)
		}
	}
	return a, func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := runEnv(args, &out, &errb, e)
		return code, out.String(), errb.String()
	}
}

func TestUsageCommandPrintsHumanUnits(t *testing.T) {
	a, run := usageHarness(t, true)
	a.reply = `{"bytes":13002342,"maxBytes":104857600,"bundles":3,"maxBundles":50,"maxBundleVersions":200}`
	code, out, errb := run("usage")
	if code != 0 || errb != "" {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if r := a.reqs[0]; r.method != "GET" || r.path != "/v1/auth/usage" || r.auth != "Bearer tok-123" {
		t.Fatalf("%+v", r)
	}
	for _, want := range []string{"12.4 MiB", "100.0 MiB", "12%", "3 of 50", "200"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestUsageCommandUnlimited(t *testing.T) {
	a, run := usageHarness(t, true)
	a.reply = `{"bytes":5,"maxBytes":0,"bundles":1,"maxBundles":0,"maxBundleVersions":0}`
	code, out, _ := run("usage")
	if code != 0 || strings.Count(out, "unlimited") != 3 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestUsageCommandNeedsLoginAndNoArgs(t *testing.T) {
	a, run := usageHarness(t, false)
	if code, _, errb := run("usage"); code != 1 || !strings.Contains(errb, "capm login") {
		t.Fatalf("exit %d, stderr %q", code, errb)
	}
	if len(a.reqs) != 0 {
		t.Fatal("made a request while logged out")
	}
	_, run2 := usageHarness(t, true)
	if code, _, _ := run2("usage", "extra"); code != 2 {
		t.Fatalf("exit %d", code)
	}
}

func TestUsageCommandOlderServer(t *testing.T) {
	a, run := usageHarness(t, true)
	a.status, a.reply = 404, "404 page not found\n"
	code, out, errb := run("usage")
	if code != 1 || out != "" || !strings.Contains(errb, "does not report usage") || strings.Contains(errb, "404") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, out, errb)
	}
}

func TestUsageCommandOtherErrors(t *testing.T) {
	a, run := usageHarness(t, true)
	a.status, a.reply = 401, `{"error":"authentication required"}`
	code, _, errb := run("usage")
	if code != 1 || !strings.Contains(errb, "authentication required") {
		t.Fatalf("exit %d, stderr %q", code, errb)
	}
}

const quotaReply = `{"id":5,"bytes":1048576,"maxBytes":104857600,"bundles":2,"maxBundles":50,"maxBundleVersions":200,"bytesOverridden":false,"bundlesOverridden":false}`

func TestAdminQuotaShow(t *testing.T) {
	a, run := adminHarness(t)
	a.reply = quotaReply
	code, out, errb := run("quota", "bob")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if r := a.reqs[0]; r.method != "GET" || r.path != "/v1/admin/users/bob/quota" || r.auth != "Bearer tok-123" {
		t.Fatalf("%+v", r)
	}
	for _, want := range []string{"1.0 MiB", "100.0 MiB", "2 of 50", "default"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "override") {
		t.Errorf("nothing is overridden:\n%s", out)
	}
	a.reply = `{"id":5,"bytes":1,"maxBytes":524288000,"bundles":2,"maxBundles":50,"maxBundleVersions":200,"bytesOverridden":true,"bundlesOverridden":false}`
	if _, out, _ = run("quota", "5"); !strings.Contains(out, "500.0 MiB (override)") || a.reqs[1].path != "/v1/admin/users/5/quota" {
		t.Errorf("output:\n%s", out)
	}
}

func putBody(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("%q: %v", raw, err)
	}
	return m
}

func TestAdminQuotaSetBytesAndBundles(t *testing.T) {
	a, run := adminHarness(t)
	a.reply = quotaReply
	code, out, errb := run("quota", "bob", "--bytes", "500MiB", "--bundles=80")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	r := a.reqs[len(a.reqs)-1]
	if r.method != "PUT" || r.path != "/v1/admin/users/bob/quota" {
		t.Fatalf("%+v", r)
	}
	if m := putBody(t, r.body); m["maxBytes"] != float64(500<<20) || m["maxBundles"] != float64(80) {
		t.Fatalf("body %s", r.body)
	}
	if !strings.Contains(out, "Updated") {
		t.Errorf("stdout %q", out)
	}
}

func TestAdminQuotaSetOneKeepsTheOtherOverride(t *testing.T) {
	a, run := adminHarness(t)
	a.reply = `{"id":5,"bytes":1,"maxBytes":104857600,"bundles":2,"maxBundles":80,"maxBundleVersions":200,"bytesOverridden":false,"bundlesOverridden":true}`
	if code, _, errb := run("quota", "bob", "--bytes", "2GiB"); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	r := a.reqs[len(a.reqs)-1]
	if m := putBody(t, r.body); m["maxBytes"] != float64(2<<30) || m["maxBundles"] != float64(80) {
		t.Fatalf("existing bundles override must be kept: %s", r.body)
	}
	// An un-overridden other limit stays null (default), not frozen at today's default.
	a.reply = quotaReply
	run("quota", "bob", "--bundles", "9")
	r = a.reqs[len(a.reqs)-1]
	if m := putBody(t, r.body); m["maxBytes"] != nil || m["maxBundles"] != float64(9) {
		t.Fatalf("body %s", r.body)
	}
}

func TestAdminQuotaReset(t *testing.T) {
	a, run := adminHarness(t)
	a.reply = quotaReply
	if code, _, errb := run("quota", "bob", "--reset"); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	r := a.reqs[len(a.reqs)-1]
	if r.method != "PUT" {
		t.Fatalf("%+v", r)
	}
	if m := putBody(t, r.body); m["maxBytes"] != nil || m["maxBundles"] != nil || len(m) != 2 {
		t.Fatalf("body %s", r.body)
	}
}

func TestAdminQuotaBadArgs(t *testing.T) {
	a, run := adminHarness(t)
	for _, args := range [][]string{
		{"quota"},
		{"quota", "bob", "extra"},
		{"quota", "bob", "--bytes"},
		{"quota", "bob", "--bytes", "lots"},
		{"quota", "bob", "--bytes", "-5"},
		{"quota", "bob", "--bundles", "x"},
		{"quota", "bob", "--bundles", "-1"},
		{"quota", "bob", "--reset", "--bytes", "1MiB"},
		{"quota", "bob", "--reset", "--bundles", "1"},
		{"quota", "bob", "--bogus"},
		{"quota", "bob", "--reason", "x"},
	} {
		code, out, errb := run(args...)
		if code != 2 || out != "" || !strings.Contains(errb, "capm admin quota") {
			t.Errorf("%v: exit %d, stdout %q, stderr %q", args, code, out, errb)
		}
	}
	if len(a.reqs) != 0 {
		t.Fatalf("requests made for bad arguments: %+v", a.reqs)
	}
}

func TestAdminQuotaNotFoundAndEscaping(t *testing.T) {
	a, run := adminHarness(t)
	a.status, a.reply = 404, `{"error":"not found"}`
	code, _, errb := run("quota", "ghost")
	if code != 1 || !strings.Contains(errb, "not found") {
		t.Fatalf("exit %d: %s", code, errb)
	}
	a.status, a.reply = 200, quotaReply
	run("quota", "a/b")
	if r := a.reqs[len(a.reqs)-1]; r.path != "/v1/admin/users/a%2Fb/quota" {
		t.Fatalf("login must be path-escaped: %+v", r)
	}
}

func TestAdminUsageListsQuota(t *testing.T) {
	_, run := adminHarness(t)
	_, out, _ := run()
	if !strings.Contains(out, "capm admin quota") {
		t.Errorf("admin usage should list quota:\n%s", out)
	}
}

func TestPushPrintsQuotaMessageAsIs(t *testing.T) {
	h := newHarness(t)
	h.mustLogin(t)
	h.reg.pushCode = 413
	h.reg.pushLimit = "user_bytes"
	h.reg.pushMsg = "storage limit reached: you store 99.0 MiB of your 100.0 MiB limit and this bundle would exceed it\x1b[2J.\nok"
	if code := h.run("push", testBundleDir(t, "a", "1.0.0")); code != 1 {
		t.Fatalf("exit %d", code)
	}
	got := h.errb.String()
	if !strings.Contains(got, "capm push: storage limit reached: you store 99.0 MiB of your 100.0 MiB limit") {
		t.Errorf("stderr %q", got)
	}
	if strings.Contains(got, "registry error") || strings.Contains(got, "413") || strings.Contains(got, "\x1b") || strings.Count(got, "\n") != 1 {
		t.Errorf("not as-is/sanitised: %q", got)
	}
}

func TestPushOversizedUploadStillGenericError(t *testing.T) {
	h := newHarness(t)
	h.mustLogin(t)
	h.reg.pushCode = 413
	h.reg.pushMsg = "bundle too large"
	if code := h.run("push", testBundleDir(t, "a", "1.0.0")); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.errb.String(), "registry error (413): bundle too large") {
		t.Errorf("stderr %q", h.errb.String())
	}
}

func TestPushRegistryFull507(t *testing.T) {
	h := newHarness(t)
	h.mustLogin(t)
	h.reg.pushCode = 507
	h.reg.pushLimit = "total_bytes"
	h.reg.pushMsg = "the registry is full and is not accepting new uploads right now; the operator has been alerted. Try again later"
	if code := h.run("push", testBundleDir(t, "a", "1.0.0")); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if got := h.errb.String(); !strings.Contains(got, "capm push: the registry is full") || strings.Contains(got, "507") {
		t.Errorf("stderr %q", got)
	}
}
