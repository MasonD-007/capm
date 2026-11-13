package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitRepositoryFlagWritesTheClaim(t *testing.T) {
	h := initHarness(t, false, "")
	dir := filepath.Join(t.TempDir(), "demo")
	if code := h.run("init", "--yes", "--name", "demo", "--repository", "https://github.com/alice/demo", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	m := loadDir(t, dir)
	if m.Metadata.Repository != "https://github.com/alice/demo" {
		t.Fatalf("%q", m.Metadata.Repository)
	}
	// Without the flag the manifest carries a commented hint and no claim.
	h2 := initHarness(t, false, "")
	dir2 := filepath.Join(t.TempDir(), "demo")
	if code := h2.run("init", "--yes", "--name", "demo", dir2); code != 0 {
		t.Fatal(h2.errb.String())
	}
	raw, _ := os.ReadFile(filepath.Join(dir2, "capm.yaml"))
	if m := loadDir(t, dir2); m.Metadata.Repository != "" || !strings.Contains(string(raw), "# repository: https://github.com/") {
		t.Fatalf("%q\n%s", m.Metadata.Repository, raw)
	}
}

func TestInitRepositoryFlagIsValidatedBeforeAnythingIsWritten(t *testing.T) {
	for _, bad := range []string{"https://github.com/a/b/", "https://github.com/a/b.git", "http://github.com/a/b",
		"https://gitlab.com/a/b", "github.com/a/b", "https://github.com/a/b\nx: y"} {
		h := initHarness(t, false, "")
		dir := filepath.Join(t.TempDir(), "demo")
		code := h.run("init", "--yes", "--repository", bad, dir)
		if code != 2 || !strings.Contains(h.errb.String(), "--repository") {
			t.Errorf("%q: exit %d %q", bad, code, h.errb.String())
		}
		if _, err := os.Stat(dir); err == nil {
			t.Errorf("%q: directory created", bad)
		}
		if strings.Contains(h.errb.String(), "\n"+"x: y") {
			t.Errorf("control characters echoed: %q", h.errb.String())
		}
	}
}

func TestInitInteractiveRepositoryQuestionIsLastAndOptional(t *testing.T) {
	// name, description, authors, base, base version, egress, mount, secrets,
	// mcp, starter prompt, then the repository.
	answers := "demo\n\n\n\n\n\n\n\n\n\nhttps://github.com/alice/demo\n"
	h := initHarness(t, true, answers)
	dir := filepath.Join(t.TempDir(), "demo")
	if code := h.run("init", dir); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, h.out.String(), h.errb.String())
	}
	if m := loadDir(t, dir); m.Metadata.Repository != "https://github.com/alice/demo" {
		t.Fatalf("%q", m.Metadata.Repository)
	}
	// Input that ends before the question skips it (earlier scripts keep working).
	h2 := initHarness(t, true, "demo\n\n\n\n\n\n\n\n\n\n")
	dir2 := filepath.Join(t.TempDir(), "demo")
	if code := h2.run("init", dir2); code != 0 {
		t.Fatalf("exit %d\n%s", code, h2.errb.String())
	}
	if m := loadDir(t, dir2); m.Metadata.Repository != "" {
		t.Fatalf("%q", m.Metadata.Repository)
	}
	// A bad answer is asked again.
	h3 := initHarness(t, true, "demo\n\n\n\n\n\n\n\n\n\nhttps://example.com/a/b\nhttps://github.com/alice/demo\n")
	dir3 := filepath.Join(t.TempDir(), "demo")
	if code := h3.run("init", dir3); code != 0 {
		t.Fatalf("exit %d\n%s", code, h3.errb.String())
	}
	if m := loadDir(t, dir3); m.Metadata.Repository != "https://github.com/alice/demo" || !strings.Contains(h3.out.String(), "exactly") {
		t.Fatalf("%q\n%s", m.Metadata.Repository, h3.out.String())
	}
}
