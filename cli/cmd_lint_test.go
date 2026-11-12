package main

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// lintManifest is a complete, valid manifest (description and authors set).
func lintManifest(name, version, context string) string {
	y := "apiVersion: capm/v0\nkind: Agent\nmetadata:\n  name: " + name + "\n  version: " + version + "\n" +
		"  description: A test bundle.\n  authors: [tester]\n" +
		"base: {agent: claude-code, version: 2.1.292}\ninterface: {type: tty}\n" +
		"model: {api: openai-compatible, requires: {toolCalling: true, minContextTokens: 1000}}\n" +
		"permissions: {egress: [api.github.com]}\n"
	if context != "" {
		y += "context: [" + context + "]\n"
	}
	return y
}

func writeFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func lintBundle(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	writeFiles(t, dir, files)
	return dir
}

func TestLintCleanBundle(t *testing.T) {
	h := newHarness(t)
	dir := lintBundle(t, map[string]string{"capm.yaml": lintManifest("a", "1.0.0", "prompts/a.md"), "prompts/a.md": "hello", "README.md": "# a"})
	if code := h.run("lint", "--offline", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if !strings.Contains(h.errb.String(), "capm lint: no problems found") {
		t.Errorf("stderr %q", h.errb.String())
	}
	if !strings.Contains(h.out.String(), "Risk labels") {
		t.Errorf("stdout lacks risk labels: %q", h.out.String())
	}
	if strings.Contains(h.errb.String(), "Risk labels") {
		t.Error("risk labels must go to stdout")
	}
}

func TestLintDefaultsToCurrentDirectory(t *testing.T) {
	h := newHarness(t)
	dir := lintBundle(t, map[string]string{"capm.yaml": lintManifest("a", "1.0.0", "")})
	t.Chdir(dir)
	if code := h.run("lint", "--offline"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
}

func TestLintManifestErrors(t *testing.T) {
	h := newHarness(t)
	bad := lintBundle(t, map[string]string{"capm.yaml": "apiVersion: capm/v0\nkind: Agent\n"})
	if code := h.run("lint", "--offline", bad); code != 1 || !strings.Contains(h.errb.String(), "invalid manifest") {
		t.Errorf("invalid: %d %q", code, h.errb.String())
	}
	if code := h.run("lint", "--offline", t.TempDir()); code != 1 {
		t.Errorf("missing capm.yaml: %d", code)
	}
	typo := lintBundle(t, map[string]string{"capm.yaml": lintManifest("a", "1.0.0", "") + "runtime: {}\n"})
	if code := h.run("lint", "--offline", typo); code != 1 || !strings.Contains(h.errb.String(), "invalid manifest") {
		t.Errorf("unknown field: %d %q", code, h.errb.String())
	}
}

func TestLintUsage(t *testing.T) {
	h := newHarness(t)
	for _, args := range [][]string{{"lint", "--nope"}, {"lint", "a", "b"}, {"lint", "--strict=maybe"}} {
		if code := h.run(args...); code != 2 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestLintWarningsAndStrict(t *testing.T) {
	h := newHarness(t)
	y := strings.NewReplacer("  description: A test bundle.\n", "", "  authors: [tester]\n", "").Replace(lintManifest("a", "1.0.0", ""))
	dir := lintBundle(t, map[string]string{"capm.yaml": y})
	if code := h.run("lint", "--offline", dir); code != 0 {
		t.Fatalf("warnings must not fail: %d", code)
	}
	for _, want := range []string{"warning[no_description]: ", "warning[no_authors]: ", "0 errors, 2 warnings"} {
		if !strings.Contains(h.errb.String(), want) {
			t.Errorf("stderr lacks %q: %q", want, h.errb.String())
		}
	}
	if !strings.Contains(h.out.String(), "Risk labels") {
		t.Error("risk labels still printed with warnings")
	}
	if code := h.run("lint", "--offline", "--strict", dir); code != 1 {
		t.Errorf("--strict: %d", code)
	}
	if code := h.run("lint", dir, "--offline", "--strict"); code != 1 {
		t.Errorf("flags after dir: %d", code)
	}
}

func TestLintContextMissing(t *testing.T) {
	h := newHarness(t)
	dir := lintBundle(t, map[string]string{"capm.yaml": lintManifest("a", "1.0.0", "gone.md, adir, link.md"), "real.md": "x"})
	os.Mkdir(filepath.Join(dir, "adir"), 0o755)
	os.Symlink("real.md", filepath.Join(dir, "link.md"))
	if code := h.run("lint", "--offline", dir); code != 1 {
		t.Fatalf("exit %d", code)
	}
	s := h.errb.String()
	for _, want := range []string{`error[context_missing]: "gone.md" cannot be packed: it does not exist`,
		`"adir" cannot be packed: it is not a regular file`, `"link.md" cannot be packed: it is or traverses a symlink`, "3 errors, "} {
		if !strings.Contains(s, want) {
			t.Errorf("stderr lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, dir) {
		t.Error("absolute temp path leaked into the message")
	}
}

func TestLintContextUnlisted(t *testing.T) {
	h := newHarness(t)
	files := map[string]string{"capm.yaml": lintManifest("a", "1.0.0", "prompts/a.md"), "prompts/a.md": "x", "README.md": "r",
		".git/config": "x", "notes/.hidden/z.md": "z", "sub/deep/b.md": "b"}
	for i := 0; i < 12; i++ {
		files[fmt.Sprintf("extra/f%02d.md", i)] = "x"
	}
	dir := lintBundle(t, files)
	if code := h.run("lint", "--offline", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	s := h.errb.String()
	if n := strings.Count(s, "warning[context_unlisted]"); n != 11 { // 10 files + "and N more"
		t.Errorf("%d unlisted findings:\n%s", n, s)
	}
	for _, want := range []string{"NOT published", "and 3 more unlisted files", "11 warnings"} {
		if !strings.Contains(s, want) {
			t.Errorf("stderr lacks %q:\n%s", want, s)
		}
	}
	for _, not := range []string{".git", "prompts/a.md", "README.md", ".hidden"} {
		if strings.Contains(s, not) {
			t.Errorf("stderr mentions %q:\n%s", not, s)
		}
	}
}

func TestLintSecretFileInPackedFiles(t *testing.T) {
	h := newHarness(t)
	// Listed context named .env with a token: both the name and the content rule fire.
	dir := lintBundle(t, map[string]string{"capm.yaml": lintManifest("a", "1.0.0", "cfg/.env, prompts/p.md, notes.pem"),
		"cfg/.env": "A=1\nTOKEN=" + fakeGH + "\n", "prompts/p.md": "line1\nline2\n" + fakeAWS + "\n", "notes.pem": "x"})
	if code := h.run("lint", "--offline", dir); code != 1 {
		t.Fatalf("exit %d", code)
	}
	s := h.errb.String()
	for _, want := range []string{
		"error[secret_file]: cfg/.env would be published and its file name looks like a credential file (.env)",
		"error[secret_file]: cfg/.env:2 would be published and contains what looks like a credential (github-token)",
		"error[secret_file]: prompts/p.md:3 ", "(aws-access-key-id)",
		"notes.pem would be published", "4 errors",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("stderr lacks %q:\n%s", want, s)
		}
	}
	for _, secret := range []string{fakeGH, fakeAWS, "ghp_"} {
		if strings.Contains(s+h.out.String(), secret) {
			t.Errorf("output leaks %q", secret)
		}
	}
}

func TestLintSecretInManifestAndReadme(t *testing.T) {
	h := newHarness(t)
	y := strings.Replace(lintManifest("a", "1.0.0", ""), "A test bundle.", "key "+fakeAnth, 1)
	dir := lintBundle(t, map[string]string{"capm.yaml": y, "README.md": "slack " + fakeSlack + "\n"})
	if code := h.run("lint", "--offline", dir); code != 1 {
		t.Fatalf("exit %d", code)
	}
	s := h.errb.String()
	if !strings.Contains(s, "capm.yaml:") || !strings.Contains(s, "anthropic-api-key") || !strings.Contains(s, "README.md:1") || !strings.Contains(s, "slack-token") {
		t.Errorf("stderr:\n%s", s)
	}
	if strings.Contains(s+h.out.String(), fakeAnth) || strings.Contains(s+h.out.String(), fakeSlack) {
		t.Error("leak")
	}
}

func TestLintSecretFileNearby(t *testing.T) {
	h := newHarness(t)
	dir := lintBundle(t, map[string]string{"capm.yaml": lintManifest("a", "1.0.0", ""), ".env": "X=1", "dev/.env.local": "Y=2",
		".env.example": "X=", "dev/notes.txt": "token " + fakeGH, "id_rsa": "k"})
	if code := h.run("lint", "--offline", dir); code != 0 {
		t.Fatalf("nearby is only a warning, exit %d:\n%s", code, h.errb.String())
	}
	s := h.errb.String()
	for _, want := range []string{"warning[secret_file_nearby]: .env is not published but sits next to the bundle",
		"dev/.env.local is not published", "id_rsa is not published", "dev/notes.txt is not published", "github-token"} {
		if !strings.Contains(s, want) {
			t.Errorf("stderr lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "secret_file]") {
		t.Errorf("unpacked files must not be errors:\n%s", s)
	}
	if strings.Contains(s, ".env.example is not published but sits") {
		t.Errorf(".env.example flagged:\n%s", s)
	}
	if strings.Contains(s, fakeGH) {
		t.Error("leak")
	}
}

func TestLintSizeNearLimit(t *testing.T) {
	h := newHarness(t)
	blob := make([]byte, 4500000) // incompressible
	rand.Read(blob)
	dir := lintBundle(t, map[string]string{"capm.yaml": lintManifest("a", "1.0.0", "big.bin")})
	os.WriteFile(filepath.Join(dir, "big.bin"), blob, 0o644)
	if code := h.run("lint", "--offline", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if !strings.Contains(h.errb.String(), "warning[size_near_limit]") || !strings.Contains(h.errb.String(), "5 MiB publish limit") {
		t.Errorf("stderr %q", h.errb.String())
	}
	small := lintBundle(t, map[string]string{"capm.yaml": lintManifest("a", "1.0.0", "")})
	h.run("lint", "--offline", small)
	if strings.Contains(h.errb.String(), "size_near_limit") {
		t.Error("small bundle flagged")
	}
}

func TestLintSanitisesPaths(t *testing.T) {
	h := newHarness(t)
	dir := lintBundle(t, map[string]string{"capm.yaml": lintManifest("a", "1.0.0", ""), "evil\x1b[31mname.md": "x"})
	h.run("lint", "--offline", dir)
	if strings.Contains(h.errb.String(), "\x1b") {
		t.Errorf("escape sequence reached the terminal: %q", h.errb.String())
	}
	if !strings.Contains(h.errb.String(), "context_unlisted") {
		t.Errorf("file not reported: %q", h.errb.String())
	}
}

// versionRegistry serves GET /v1/bundles/{owner}/{name} and counts requests.
func versionRegistry(t *testing.T, status int, versions ...string) (*httptest.Server, *atomic.Int32) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/v1/bundles/alice/a" {
			w.WriteHeader(500)
			return
		}
		if status != 200 {
			w.WriteHeader(status)
			fmt.Fprint(w, `{"error":"bundle not found"}`)
			return
		}
		var out []map[string]any
		for _, v := range versions {
			out = append(out, map[string]any{"version": v, "digest": "sha256:x", "yanked": false})
		}
		json.NewEncoder(w).Encode(out)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func TestLintVersionNotBumped(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		existing []string
		version  string
		want     string // substring of stderr; "" means no version finding
	}{
		{"exists", 200, []string{"1.0.0", "1.1.0"}, "1.1.0", "warning[version_not_bumped]: version 1.1.0 already exists"},
		{"lower", 200, []string{"1.0.0", "1.2.0"}, "1.1.0", "warning[version_not_bumped]: version 1.1.0 is lower than the latest published version 1.2.0"},
		{"prerelease lower", 200, []string{"1.0.0"}, "1.0.0-rc.1", "is lower than the latest published version 1.0.0"},
		{"higher", 200, []string{"1.0.0"}, "1.0.1", ""},
		{"prerelease higher", 200, []string{"1.0.0-beta.2"}, "1.0.0-beta.11", ""},
		{"new bundle", 404, nil, "0.1.0", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			srv, _ := versionRegistry(t, c.status, c.existing...)
			h.env.registry = srv.URL
			if err := saveCreds(h.env, credentials{Registry: srv.URL, Login: "alice", Token: "tok"}); err != nil {
				t.Fatal(err)
			}
			dir := lintBundle(t, map[string]string{"capm.yaml": lintManifest("a", c.version, "")})
			if code := h.run("lint", dir); code != 0 {
				t.Fatalf("exit %d: %s", code, h.errb.String())
			}
			s := h.errb.String()
			if c.want == "" && strings.Contains(s, "version_not_bumped") {
				t.Errorf("unexpected finding:\n%s", s)
			}
			if c.want != "" && !strings.Contains(s, c.want) {
				t.Errorf("stderr lacks %q:\n%s", c.want, s)
			}
			if c.want == "" && !strings.Contains(s, "no problems found") {
				t.Errorf("stderr:\n%s", s)
			}
		})
	}
}

func TestLintVersionSkips(t *testing.T) {
	// Offline: no request at all, even when logged in.
	h := newHarness(t)
	srv, hits := versionRegistry(t, 200, "1.0.0")
	h.env.registry = srv.URL
	saveCreds(h.env, credentials{Registry: srv.URL, Login: "alice", Token: "tok"})
	dir := lintBundle(t, map[string]string{"capm.yaml": lintManifest("a", "1.0.0", "")})
	if code := h.run("lint", "--offline", dir); code != 0 || hits.Load() != 0 {
		t.Errorf("offline: exit %d hits %d", code, hits.Load())
	}
	// Not logged in: one note, no request, exit 0.
	h2 := newHarness(t)
	h2.env.registry = srv.URL
	if code := h2.run("lint", dir); code != 0 || hits.Load() != 0 {
		t.Errorf("anon: exit %d hits %d", code, hits.Load())
	}
	if n := strings.Count(h2.errb.String(), "note: "); n != 1 || !strings.Contains(h2.errb.String(), "version_not_bumped") || !strings.Contains(h2.errb.String(), "not logged in") {
		t.Errorf("anon stderr: %q", h2.errb.String())
	}
	// Server error: note, exit 0.
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer bad.Close()
	h3 := newHarness(t)
	h3.env.registry = bad.URL
	saveCreds(h3.env, credentials{Registry: bad.URL, Login: "alice", Token: "tok"})
	if code := h3.run("lint", dir); code != 0 || !strings.Contains(h3.errb.String(), "note: version_not_bumped skipped") {
		t.Errorf("500: exit %d %q", code, h3.errb.String())
	}
	// Unroutable registry.
	h4 := newHarness(t)
	h4.env.registry = "http://127.0.0.1:1"
	saveCreds(h4.env, credentials{Registry: h4.env.registry, Login: "alice", Token: "tok"})
	if code := h4.run("lint", dir); code != 0 || !strings.Contains(h4.errb.String(), "note: version_not_bumped skipped") {
		t.Errorf("unreachable: exit %d %q", code, h4.errb.String())
	}
}
