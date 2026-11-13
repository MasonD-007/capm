package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// fakeRelease serves a GitHub-like release: GET /releases/latest redirects to
// /releases/tag/<tag>, and /download/<asset> serves assets and checksums.txt.
type fakeRelease struct {
	srv       *httptest.Server
	tag       string
	assets    map[string][]byte // by asset name
	checksums *string           // nil: computed from assets
	mu        sync.Mutex
	hits      []string
	agents    []string
}

func sumHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func newFakeRelease(t *testing.T, tag string, assets map[string][]byte) *fakeRelease {
	t.Helper()
	fr := &fakeRelease{tag: tag, assets: assets}
	fr.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fr.mu.Lock()
		fr.hits = append(fr.hits, r.URL.Path)
		fr.agents = append(fr.agents, r.Header.Get("User-Agent"))
		fr.mu.Unlock()
		switch {
		case r.URL.Path == "/releases/latest":
			http.Redirect(w, r, "/releases/tag/"+fr.tag, http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/releases/tag/"):
			fmt.Fprint(w, "<html>release page</html>")
		case r.URL.Path == "/download/checksums.txt":
			if fr.checksums != nil {
				fmt.Fprint(w, *fr.checksums)
				return
			}
			for name, b := range fr.assets {
				fmt.Fprintf(w, "%s  %s\n", sumHex(b), name)
			}
		case strings.HasPrefix(r.URL.Path, "/download/"):
			b, ok := fr.assets[strings.TrimPrefix(r.URL.Path, "/download/")]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fr.srv.Close)
	return fr
}

func (fr *fakeRelease) assetName() string { return "capm-" + runtime.GOOS + "-" + runtime.GOARCH }

func fakeBinary(v string) []byte {
	return []byte("#!/bin/sh\necho \"capm " + v + "\"\n")
}

// setVersion sets the running CLI version for one test.
func setVersion(t *testing.T, v string) {
	t.Helper()
	old := version
	version = v
	t.Cleanup(func() { version = old })
}

// updateFixture is a temp "installed" executable plus an env pointing at fr.
type updateFixture struct {
	dir, exe string
	e        env
	fr       *fakeRelease
}

func newUpdateFixture(t *testing.T, current, latestTag string) *updateFixture {
	t.Helper()
	setVersion(t, current)
	dir := t.TempDir()
	exe := filepath.Join(dir, "capm")
	if err := os.WriteFile(exe, fakeBinary(current), 0o755); err != nil {
		t.Fatal(err)
	}
	f := &updateFixture{dir: dir, exe: exe}
	f.fr = newFakeRelease(t, latestTag, nil)
	f.fr.assets = map[string][]byte{f.fr.assetName(): fakeBinary(strings.TrimPrefix(latestTag, "v"))}
	f.e = env{registry: "http://unused.invalid", credDir: t.TempDir()}
	f.e.upd = updateEnv{
		hc:           f.fr.srv.Client(),
		latestURL:    f.fr.srv.URL + "/releases/latest",
		downloadBase: f.fr.srv.URL + "/download",
		exePath:      func() (string, error) { return exe, nil },
	}
	return f
}

func (f *updateFixture) run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := runEnv(args, &out, &errb, f.e)
	return code, out.String(), errb.String()
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func noStrayTemps(t *testing.T, dir string) {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		if e.Name() != "capm" {
			t.Errorf("stray file left in install dir: %s", e.Name())
		}
	}
}

func TestSelfUpdateHappyPath(t *testing.T) {
	f := newUpdateFixture(t, "0.1.0", "v0.2.0")
	code, out, errb := f.run("self-update")
	if code != 0 {
		t.Fatalf("exit %d\nstdout: %s\nstderr: %s", code, out, errb)
	}
	if got := mustRead(t, f.exe); !bytes.Equal(got, fakeBinary("0.2.0")) {
		t.Fatalf("executable not replaced: %q", got)
	}
	fi, _ := os.Stat(f.exe)
	if fi.Mode().Perm() != 0o755 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	if !strings.Contains(out, "capm 0.2.0") {
		t.Fatalf("new version not printed from the new binary: %q", out)
	}
	if !strings.Contains(errb, "0.1.0") || !strings.Contains(errb, "0.2.0") {
		t.Fatalf("stderr should mention both versions: %q", errb)
	}
	noStrayTemps(t, f.dir)
}

func TestSelfUpdateSendsPlainUserAgent(t *testing.T) {
	f := newUpdateFixture(t, "0.1.0", "v0.2.0")
	f.run("self-update")
	f.fr.mu.Lock()
	defer f.fr.mu.Unlock()
	for _, a := range f.fr.agents {
		if a != "capm/0.1.0" {
			t.Fatalf("user agent %q", a)
		}
	}
}

func TestSelfUpdateAlreadyCurrent(t *testing.T) {
	f := newUpdateFixture(t, "0.2.0", "v0.2.0")
	before := mustRead(t, f.exe)
	code, _, errb := f.run("self-update")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if !strings.Contains(errb, "up to date") {
		t.Fatalf("stderr: %q", errb)
	}
	if !bytes.Equal(mustRead(t, f.exe), before) {
		t.Fatal("file changed")
	}
	for _, h := range f.fr.hits {
		if strings.HasPrefix(h, "/download/") {
			t.Fatalf("downloaded although current: %v", f.fr.hits)
		}
	}
}

func TestSelfUpdateNewerThanLatestDoesNothing(t *testing.T) {
	f := newUpdateFixture(t, "0.3.0", "v0.2.0")
	before := mustRead(t, f.exe)
	code, _, _ := f.run("self-update")
	if code != 0 || !bytes.Equal(mustRead(t, f.exe), before) {
		t.Fatalf("exit %d, file changed=%v", code, !bytes.Equal(mustRead(t, f.exe), before))
	}
}

func TestSelfUpdateChecksumMismatchLeavesOriginal(t *testing.T) {
	f := newUpdateFixture(t, "0.1.0", "v0.2.0")
	orig := mustRead(t, f.exe)
	bad := strings.Repeat("0", 64)
	cs := bad + "  " + f.fr.assetName() + "\n"
	f.fr.checksums = &cs
	code, out, errb := f.run("self-update")
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !bytes.Equal(mustRead(t, f.exe), orig) {
		t.Fatal("original changed")
	}
	want := sumHex(f.fr.assets[f.fr.assetName()])
	if !strings.Contains(errb, bad) || !strings.Contains(errb, want) {
		t.Fatalf("both hashes should be printed:\n%s", errb)
	}
	if strings.Contains(out, "capm 0.2.0") {
		t.Fatalf("stdout: %q", out)
	}
	noStrayTemps(t, f.dir)
}

func TestSelfUpdateChecksumsMissingAsset(t *testing.T) {
	f := newUpdateFixture(t, "0.1.0", "v0.2.0")
	orig := mustRead(t, f.exe)
	cs := sumHex([]byte("x")) + "  capm-plan9-mips\n"
	f.fr.checksums = &cs
	code, _, errb := f.run("self-update")
	if code != 1 || !bytes.Equal(mustRead(t, f.exe), orig) {
		t.Fatalf("exit %d, unchanged=%v", code, bytes.Equal(mustRead(t, f.exe), orig))
	}
	if !strings.Contains(errb, f.fr.assetName()) {
		t.Fatalf("stderr should name the asset: %q", errb)
	}
}

func TestSelfUpdateAsset404(t *testing.T) {
	f := newUpdateFixture(t, "0.1.0", "v0.2.0")
	orig := mustRead(t, f.exe)
	f.fr.assets = map[string][]byte{}
	cs := sumHex([]byte("x")) + "  " + f.fr.assetName() + "\n"
	f.fr.checksums = &cs
	code, _, errb := f.run("self-update")
	if code != 1 || !bytes.Equal(mustRead(t, f.exe), orig) {
		t.Fatalf("exit %d, unchanged=%v", code, bytes.Equal(mustRead(t, f.exe), orig))
	}
	if !strings.Contains(errb, "404") {
		t.Fatalf("stderr: %q", errb)
	}
	noStrayTemps(t, f.dir)
}

func TestSelfUpdateUnwritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	f := newUpdateFixture(t, "0.1.0", "v0.2.0")
	orig := mustRead(t, f.exe)
	if err := os.Chmod(f.dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(f.dir, 0o755) })
	code, _, errb := f.run("self-update")
	if code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb, "not writable") || !strings.Contains(errb, f.dir) {
		t.Fatalf("stderr: %q", errb)
	}
	if !bytes.Equal(mustRead(t, f.exe), orig) {
		t.Fatal("original changed")
	}
	for _, h := range f.fr.hits {
		if strings.HasPrefix(h, "/download/") {
			t.Fatalf("should refuse before downloading: %v", f.fr.hits)
		}
	}
}

func TestSelfUpdateRefusesPackageManagerPaths(t *testing.T) {
	for _, p := range []string{
		"/opt/homebrew/Cellar/capm/0.1.0/bin/capm",
		"/usr/local/Cellar/capm/0.1.0/bin/capm",
		"/home/linuxbrew/.linuxbrew/homebrew/bin/capm",
		"/nix/store/abc-capm-0.1.0/bin/capm",
	} {
		t.Run(p, func(t *testing.T) {
			f := newUpdateFixture(t, "0.1.0", "v0.2.0")
			f.e.upd.exePath = func() (string, error) { return p, nil }
			code, _, errb := f.run("self-update")
			if code != 1 {
				t.Fatalf("exit %d", code)
			}
			if !strings.Contains(errb, "package manager") {
				t.Fatalf("stderr: %q", errb)
			}
			if len(f.fr.hits) != 0 {
				t.Fatalf("should not touch the network: %v", f.fr.hits)
			}
		})
	}
}

func TestSelfUpdateRefusesWhenSymlinkResolvesIntoPackageManager(t *testing.T) {
	f := newUpdateFixture(t, "0.1.0", "v0.2.0")
	cellar := filepath.Join(t.TempDir(), "Cellar", "capm", "0.1.0", "bin")
	if err := os.MkdirAll(cellar, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(cellar, "capm")
	os.WriteFile(real, fakeBinary("0.1.0"), 0o755)
	link := filepath.Join(f.dir, "capm-link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	f.e.upd.exePath = func() (string, error) { return link, nil }
	code, _, errb := f.run("self-update")
	if code != 1 || !strings.Contains(errb, "package manager") {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if !bytes.Equal(mustRead(t, real), fakeBinary("0.1.0")) {
		t.Fatal("target changed")
	}
}

func TestSelfUpdateFollowsSymlinkToRealFile(t *testing.T) {
	f := newUpdateFixture(t, "0.1.0", "v0.2.0")
	link := filepath.Join(t.TempDir(), "capm")
	if err := os.Symlink(f.exe, link); err != nil {
		t.Fatal(err)
	}
	f.e.upd.exePath = func() (string, error) { return link, nil }
	if code, _, errb := f.run("self-update"); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if fi, _ := os.Lstat(link); fi.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced instead of its target")
	}
	if !bytes.Equal(mustRead(t, f.exe), fakeBinary("0.2.0")) {
		t.Fatal("target not updated")
	}
}

func TestSelfUpdateFromSHAAndDevBuilds(t *testing.T) {
	sha := strings.Repeat("ab", 20)
	for _, cur := range []string{sha, "dev"} {
		t.Run(cur[:3], func(t *testing.T) {
			f := newUpdateFixture(t, cur, "v0.2.0")
			code, out, errb := f.run("self-update")
			if code != 0 {
				t.Fatalf("exit %d: %s", code, errb)
			}
			if !bytes.Equal(mustRead(t, f.exe), fakeBinary("0.2.0")) {
				t.Fatal("not updated")
			}
			if !strings.Contains(errb, "not a released version") {
				t.Fatalf("stderr should say the build is unversioned: %q", errb)
			}
			if !strings.Contains(out, "capm 0.2.0") {
				t.Fatalf("stdout: %q", out)
			}
		})
	}
}

func TestSelfUpdateSHABuildIsCurrentWhenLatestIsItsOwnPerCommitTag(t *testing.T) {
	sha := strings.Repeat("cd", 20)
	f := newUpdateFixture(t, sha, "cli-"+sha)
	before := mustRead(t, f.exe)
	code, _, errb := f.run("self-update")
	if code != 0 || !bytes.Equal(mustRead(t, f.exe), before) {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if !strings.Contains(errb, "up to date") {
		t.Fatalf("stderr: %q", errb)
	}
}

func TestSelfUpdateDownloadBaseFromEnvVars(t *testing.T) {
	f := newUpdateFixture(t, "0.1.0", "v0.2.0")
	// Clear the injected URLs: the CAPM_* variables must supply them.
	f.e.upd.latestURL, f.e.upd.downloadBase = "", ""
	f.e.getenv = func(k string) string {
		switch k {
		case "CAPM_DOWNLOAD_BASE":
			return f.fr.srv.URL + "/download/"
		case "CAPM_LATEST_URL":
			return f.fr.srv.URL + "/releases/latest"
		}
		return ""
	}
	if code, _, errb := f.run("self-update"); code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if !bytes.Equal(mustRead(t, f.exe), fakeBinary("0.2.0")) {
		t.Fatal("not updated via env override")
	}
}

func TestSelfUpdateUnsupportedPlatform(t *testing.T) {
	f := newUpdateFixture(t, "0.1.0", "v0.2.0")
	f.e.upd.goos, f.e.upd.goarch = "windows", "amd64"
	code, _, errb := f.run("self-update")
	if code != 1 || !strings.Contains(errb, "windows/amd64") || !strings.Contains(errb, "not supported") {
		t.Fatalf("exit %d: %q", code, errb)
	}
}

func TestSelfUpdateCheck(t *testing.T) {
	t.Run("update available", func(t *testing.T) {
		f := newUpdateFixture(t, "0.1.0", "v0.2.0")
		before := mustRead(t, f.exe)
		code, out, errb := f.run("self-update", "--check")
		if code != 0 {
			t.Fatalf("exit %d", code)
		}
		if out != "current 0.1.0 latest 0.2.0\n" {
			t.Fatalf("stdout %q", out)
		}
		if !strings.Contains(errb, "available") {
			t.Fatalf("stderr %q", errb)
		}
		if !bytes.Equal(mustRead(t, f.exe), before) {
			t.Fatal("--check modified the file")
		}
		for _, h := range f.fr.hits {
			if strings.HasPrefix(h, "/download/") {
				t.Fatalf("--check downloaded: %v", f.fr.hits)
			}
		}
	})
	t.Run("current", func(t *testing.T) {
		f := newUpdateFixture(t, "0.2.0", "v0.2.0")
		code, out, errb := f.run("self-update", "--check")
		if code != 0 || out != "current 0.2.0 latest 0.2.0\n" || !strings.Contains(errb, "up to date") {
			t.Fatalf("exit %d out %q err %q", code, out, errb)
		}
	})
	t.Run("sha build is unknown, update available", func(t *testing.T) {
		sha := strings.Repeat("ef", 20)
		f := newUpdateFixture(t, sha, "v0.2.0")
		code, out, errb := f.run("self-update", "--check")
		if code != 0 || out != "current "+sha+" latest 0.2.0\n" {
			t.Fatalf("exit %d out %q", code, out)
		}
		if !strings.Contains(errb, "not a released version") {
			t.Fatalf("stderr %q", errb)
		}
	})
	t.Run("network error exits 1", func(t *testing.T) {
		f := newUpdateFixture(t, "0.1.0", "v0.2.0")
		f.fr.srv.Close()
		code, out, _ := f.run("self-update", "--check")
		if code != 1 || out != "" {
			t.Fatalf("exit %d out %q", code, out)
		}
	})
	t.Run("latest page 404 exits 1", func(t *testing.T) {
		f := newUpdateFixture(t, "0.1.0", "v0.2.0")
		f.e.upd.latestURL = f.fr.srv.URL + "/nope"
		if code, _, _ := f.run("self-update", "--check"); code != 1 {
			t.Fatalf("exit %d", code)
		}
	})
}

func TestSelfUpdateUsage(t *testing.T) {
	f := newUpdateFixture(t, "0.1.0", "v0.2.0")
	for _, args := range [][]string{{"self-update", "--bogus"}, {"self-update", "x"}} {
		if code, _, errb := f.run(args...); code != 2 || !strings.Contains(errb, "usage: capm self-update") {
			t.Fatalf("%v: exit %d: %q", args, code, errb)
		}
	}
}

func TestLatestVersionFromRedirect(t *testing.T) {
	cases := []struct{ tag, want string }{
		{"v1.2.3", "1.2.3"},
		{"v1.2.3-rc.1", "1.2.3-rc.1"},
		{"cli-" + strings.Repeat("a", 40), strings.Repeat("a", 40)},
		{"weird", "weird"},
	}
	for _, c := range cases {
		fr := newFakeRelease(t, c.tag, nil)
		got, err := latestVersion(t.Context(), fr.srv.Client(), fr.srv.URL+"/releases/latest", "capm/test")
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.tag, got, err, c.want)
		}
	}
}

func TestParseChecksums(t *testing.T) {
	h := strings.Repeat("a", 64)
	txt := h + "  capm-linux-amd64\n" + strings.Repeat("b", 64) + " *capm-darwin-arm64\nnot a line\n"
	if got, ok := checksumFor(txt, "capm-linux-amd64"); !ok || got != h {
		t.Fatalf("%q %v", got, ok)
	}
	if got, ok := checksumFor(txt, "capm-darwin-arm64"); !ok || got != strings.Repeat("b", 64) {
		t.Fatalf("%q %v", got, ok)
	}
	if _, ok := checksumFor(txt, "capm-linux-arm64"); ok {
		t.Fatal("found a missing asset")
	}
}
