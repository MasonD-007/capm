package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type hostileCase struct {
	name string
	hdr  tar.Header
	want string // substring expected in the error
}

var hostileCases = []hostileCase{
	{"traversal", tar.Header{Name: "../evil", Typeflag: tar.TypeReg}, "unsafe path"},
	{"absolute", tar.Header{Name: "/tmp/capm-evil-abs", Typeflag: tar.TypeReg}, "unsafe path"},
	{"symlink", tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}, "not a regular file"},
}

// hostileTar returns a tarball whose first entry is a VALID capm.yaml,
// followed by the hostile entry, so rejection can only come from the entry checks.
func hostileTar(t *testing.T, c hostileCase) []byte {
	t.Helper()
	yml, err := os.ReadFile(filepath.Join(testBundleDir(t, "agent", "1.0.0"), "capm.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "capm.yaml", Mode: 0o644, Size: int64(len(yml)), Typeflag: tar.TypeReg})
	tw.Write(yml)
	h := c.hdr
	h.Mode = 0o644
	body := []byte("pwned")
	if h.Typeflag == tar.TypeReg {
		h.Size = int64(len(body))
	}
	tw.WriteHeader(&h)
	if h.Typeflag == tar.TypeReg {
		tw.Write(body)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func chdirTemp(t *testing.T) string {
	root := t.TempDir()
	work := filepath.Join(root, "work")
	os.Mkdir(work, 0o755)
	t.Chdir(work)
	return root
}

func TestPullUnpacksIntoNameDir(t *testing.T) {
	h := newHarness(t)
	chdirTemp(t)
	h.reg.add("bob", "agent", "1.0.0", testBundleTar(t, "agent", "1.0.0"), false)
	if code := h.run("pull", "bob/agent"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if _, err := os.Stat(filepath.Join("agent", "capm.yaml")); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(".")
	if len(ents) != 1 {
		t.Errorf("stray entries in cwd: %v", ents)
	}
}

func TestPullHostileTarballWritesNothing(t *testing.T) {
	for _, c := range hostileCases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			root := chdirTemp(t)
			h.reg.add("bob", "agent", "1.0.0", hostileTar(t, c), false)
			if code := h.run("pull", "bob/agent@1.0.0"); code != 1 {
				t.Fatalf("exit %d", code)
			}
			if !strings.Contains(h.errb.String(), c.want) {
				t.Errorf("stderr should name the path-safety failure %q: %q", c.want, h.errb.String())
			}
			if ents, _ := os.ReadDir(root); len(ents) != 1 || ents[0].Name() != "work" {
				t.Errorf("wrote outside cwd: %v", ents)
			}
			if ents, _ := os.ReadDir("."); len(ents) != 0 {
				t.Errorf("cwd not clean after failed pull: %v", ents)
			}
			if _, err := os.Stat("/tmp/capm-evil-abs"); err == nil {
				t.Error("absolute path was written")
			}
		})
	}
}

func TestPullRefusesNonEmptyDest(t *testing.T) {
	h := newHarness(t)
	chdirTemp(t)
	h.reg.add("bob", "agent", "1.0.0", testBundleTar(t, "agent", "1.0.0"), false)
	os.Mkdir("agent", 0o755)
	os.WriteFile(filepath.Join("agent", "keep.txt"), []byte("mine"), 0o644)
	if code := h.run("pull", "bob/agent"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	ents, _ := os.ReadDir("agent")
	if len(ents) != 1 || ents[0].Name() != "keep.txt" {
		t.Errorf("dest modified: %v", ents)
	}
}

func TestPullIntoEmptyDestOK(t *testing.T) {
	h := newHarness(t)
	chdirTemp(t)
	h.reg.add("bob", "agent", "1.0.0", testBundleTar(t, "agent", "1.0.0"), false)
	os.Mkdir("agent", 0o755)
	if code := h.run("pull", "bob/agent"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if _, err := os.Stat(filepath.Join("agent", "capm.yaml")); err != nil {
		t.Fatal(err)
	}
}

func TestPullYankedExactWarnsAndLatestSkips(t *testing.T) {
	h := newHarness(t)
	chdirTemp(t)
	h.reg.add("bob", "agent", "1.0.0", testBundleTar(t, "agent", "1.0.0"), false)
	h.reg.add("bob", "agent", "1.1.0", testBundleTar(t, "agent", "1.1.0"), true)

	if code := h.run("pull", "bob/agent@1.1.0"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if !strings.Contains(h.errb.String(), "yanked") {
		t.Errorf("no yank warning: %q", h.errb.String())
	}
	b, _ := os.ReadFile(filepath.Join("agent", "capm.yaml"))
	if !strings.Contains(string(b), "1.1.0") {
		t.Errorf("exact yanked version not pulled: %s", b)
	}

	os.RemoveAll("agent")
	if code := h.run("pull", "bob/agent@latest"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	b, _ = os.ReadFile(filepath.Join("agent", "capm.yaml"))
	if !strings.Contains(string(b), "1.0.0") || strings.Contains(h.errb.String(), "yanked") {
		t.Errorf("latest should skip yanked: %s / %q", b, h.errb.String())
	}
}

func TestMalformedRefsExit2(t *testing.T) {
	h := newHarness(t)
	chdirTemp(t)
	for _, cmd := range []string{"pull", "inspect"} {
		for _, ref := range []string{"noslash@1.0.0", "a/", "/b", "a//b", "a/b/c@1.0.0", "../x@1", "a/..@1.0.0", "a/b@", "~u/b@1.0.0", "a/b@1/../2", "a/b@@1"} {
			if cmd == "inspect" && !strings.Contains(ref, "@") {
				continue // without "@" an argument may be a local path
			}
			if code := h.run(cmd, ref); code != 2 {
				t.Errorf("%s %q: exit %d, want 2", cmd, ref, code)
			}
			if !strings.Contains(h.errb.String(), "usage") {
				t.Errorf("%s %q: no usage message: %q", cmd, ref, h.errb.String())
			}
		}
	}
	if code := h.run("pull"); code != 2 {
		t.Errorf("pull no args: %d", code)
	}
}

func TestParseRef(t *testing.T) {
	o, n, v, err := parseRef("alice/x@1.2.3")
	if err != nil || o != "alice" || n != "x" || v != "1.2.3" {
		t.Fatalf("%q %q %q %v", o, n, v, err)
	}
	_, _, v, err = parseRef("alice/x")
	if err != nil || v != "latest" {
		t.Fatalf("%q %v", v, err)
	}
}

func TestInspectRemoteWritesNothing(t *testing.T) {
	h := newHarness(t)
	chdirTemp(t)
	h.reg.add("bob", "agent", "1.0.0", testBundleTar(t, "agent", "1.0.0"), false)
	if code := h.run("inspect", "bob/agent"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if !strings.Contains(h.out.String(), "api.github.com") {
		t.Errorf("summary missing: %q", h.out.String())
	}
	ents, _ := os.ReadDir(".")
	if len(ents) != 0 {
		t.Errorf("inspect wrote to cwd: %v", ents)
	}
}

func TestInspectRemoteHostileExit1(t *testing.T) {
	for _, c := range hostileCases {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t)
			root := chdirTemp(t)
			h.reg.add("bob", "agent", "1.0.0", hostileTar(t, c), false)
			if code := h.run("inspect", "bob/agent@1.0.0"); code != 1 {
				t.Fatalf("exit %d", code)
			}
			if !strings.Contains(h.errb.String(), c.want) {
				t.Errorf("stderr should name %q: %q", c.want, h.errb.String())
			}
			if ents, _ := os.ReadDir(root); len(ents) != 1 || ents[0].Name() != "work" {
				t.Errorf("wrote outside cwd: %v", ents)
			}
			if ents, _ := os.ReadDir("."); len(ents) != 0 {
				t.Errorf("cwd not clean: %v", ents)
			}
		})
	}
}

func TestInspectHeaders(t *testing.T) {
	h := newHarness(t)
	chdirTemp(t)
	h.reg.add("bob", "agent", "1.0.0", testBundleTar(t, "agent", "1.0.0"), false)
	h.reg.add("bob", "agent", "1.1.0", testBundleTar(t, "agent", "1.1.0"), false)
	if code := h.run("inspect", "bob/agent"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if !strings.Contains(h.errb.String(), "inspecting registry bob/agent@1.1.0\n") {
		t.Errorf("registry header: %q", h.errb.String())
	}
	dir := testBundleDir(t, "agent", "1.0.0")
	if code := h.run("inspect", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if !strings.Contains(h.errb.String(), "inspecting local "+dir+"\n") {
		t.Errorf("local header: %q", h.errb.String())
	}
}

const escape = "\x1b[2J\nFAKE"

func assertClean(t *testing.T, h *harness) {
	t.Helper()
	for _, s := range []string{h.out.String(), h.errb.String()} {
		if strings.ContainsRune(s, 0x1b) {
			t.Errorf("escape sequence leaked: %q", s)
		}
		if strings.Contains(s, "\nFAKE") {
			t.Errorf("newline injection: %q", s)
		}
	}
}

func TestServerStringsSanitized(t *testing.T) {
	// error body
	h := newHarness(t)
	h.mustLogin(t)
	h.reg.pushCode = 409
	h.reg.pushMsg = escape
	h.run("push", testBundleDir(t, "a", "1.0.0"))
	assertClean(t, h)
	if !strings.Contains(h.errb.String(), "registry error") {
		t.Errorf("expected error output: %q", h.errb.String())
	}
	// user_code and verification_uri
	h = newHarness(t)
	h.reg.userCode, h.reg.verifyURI = escape, escape
	h.mustLogin(t)
	assertClean(t, h)
	// resolved version
	h = newHarness(t)
	chdirTemp(t)
	h.reg.add("bob", "agent", "1.0.0", testBundleTar(t, "agent", "1.0.0"), false)
	h.reg.forceVersion = escape
	for _, args := range [][]string{{"pull", "bob/agent"}, {"inspect", "bob/agent"}, {"pull", "bob/agent@1.0.0"}} {
		if code := h.run(args...); code != 1 {
			t.Errorf("%v: exit %d, want 1", args, code)
		}
		assertClean(t, h)
	}
	if ents, _ := os.ReadDir("."); len(ents) != 0 {
		t.Errorf("cwd not clean: %v", ents)
	}
}

func TestExactPinMustMatchResolved(t *testing.T) {
	h := newHarness(t)
	chdirTemp(t)
	h.reg.add("bob", "agent", "1.0.0", testBundleTar(t, "agent", "1.0.0"), false)
	h.reg.forceVersion = "9.9.9"
	if code := h.run("pull", "bob/agent@1.0.0"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if ents, _ := os.ReadDir("."); len(ents) != 0 {
		t.Errorf("cwd not clean: %v", ents)
	}
}

func TestHostileDigestSanitized(t *testing.T) {
	h := newHarness(t)
	chdirTemp(t)
	h.reg.add("bob", "agent", "1.0.0", testBundleTar(t, "agent", "1.0.0"), false)
	h.reg.digest = "sha256:" + escape
	for _, args := range [][]string{{"pull", "bob/agent"}, {"inspect", "bob/agent"}} {
		if code := h.run(args...); code != 1 {
			t.Fatalf("%v: exit %d, want 1", args, code)
		}
		assertClean(t, h)
		if !strings.Contains(h.errb.String(), "digest") || !strings.Contains(h.errb.String(), "sha256:[2JFAKE") {
			t.Errorf("sanitized text missing: %q", h.errb.String())
		}
	}
	if ents, _ := os.ReadDir("."); len(ents) != 0 {
		t.Errorf("cwd not clean: %v", ents)
	}
}

func TestHostileLoginSanitized(t *testing.T) {
	h := newHarness(t)
	h.reg.meLogin = escape
	if code := h.run("login"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	assertClean(t, h)
	if _, err := os.Stat(filepath.Join(h.env.credDir, "credentials.json")); err == nil {
		t.Error("credentials saved for invalid login")
	}
}

// T-b: a registry that supplies no usable digest must not skip verification.
func TestMissingOrForeignDigestRefused(t *testing.T) {
	for _, d := range []string{"", "md5:abc", "sha256:", "sha256:xyz", "sha256:" + strings.Repeat("A", 64)} {
		h := newHarness(t)
		chdirTemp(t)
		h.reg.add("bob", "agent", "1.0.0", testBundleTar(t, "agent", "1.0.0"), false)
		h.reg.digest, h.reg.literalDigest = d, true
		for _, args := range [][]string{{"pull", "bob/agent"}, {"inspect", "bob/agent"}} {
			if code := h.run(args...); code != 1 {
				t.Errorf("digest %q %v: exit %d, want 1", d, args, code)
			}
			if !strings.Contains(h.errb.String(), "digest") {
				t.Errorf("digest %q %v: stderr %q", d, args, h.errb.String())
			}
		}
		if ents, _ := os.ReadDir("."); len(ents) != 0 {
			t.Errorf("cwd not clean: %v", ents)
		}
	}
}
