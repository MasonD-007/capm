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

func hostileTar(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct{ n, c string }{{"capm.yaml", "x: y\n"}, {"../evil", "pwned"}} {
		tw.WriteHeader(&tar.Header{Name: f.n, Mode: 0o644, Size: int64(len(f.c)), Typeflag: tar.TypeReg})
		tw.Write([]byte(f.c))
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
	h := newHarness(t)
	root := chdirTemp(t)
	h.reg.add("bob", "agent", "1.0.0", hostileTar(t), false)
	if code := h.run("pull", "bob/agent@1.0.0"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(root, "evil")); err == nil {
		t.Fatal("../evil was written")
	}
	ents, _ := os.ReadDir(".")
	if len(ents) != 0 {
		t.Errorf("cwd not empty after failed pull: %v", ents)
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
	h := newHarness(t)
	root := chdirTemp(t)
	h.reg.add("bob", "agent", "1.0.0", hostileTar(t), false)
	if code := h.run("inspect", "bob/agent@1.0.0"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(root, "evil")); err == nil {
		t.Fatal("../evil written")
	}
}
