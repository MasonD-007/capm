package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MasonD-007/capm/manifest"
)

func TestInspectFixture(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"inspect", "testdata/pr-reviewer"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, errb.String())
	}
	s := out.String()
	netIdx := strings.Index(s, "Network")
	mcpIdx := strings.Index(s, "MCP servers")
	if netIdx < 0 || mcpIdx < 0 || netIdx > mcpIdx {
		t.Fatalf("bad sections:\n%s", s)
	}
	if !strings.Contains(s[netIdx:mcpIdx], "api.github.com") {
		t.Errorf("Network lacks api.github.com:\n%s", s)
	}
	if strings.Contains(s[netIdx:mcpIdx], "mcp.example.com") {
		t.Errorf("MCP host under Network:\n%s", s)
	}
	if !strings.Contains(s[mcpIdx:], "mcp.example.com") {
		t.Errorf("MCP host missing:\n%s", s)
	}
}

func TestInspectInvalid(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "capm.yaml"), []byte("apiVersion: capm/v0\nkind: Agent\n"), 0o644)
	var out, errb bytes.Buffer
	if code := run([]string{"inspect", dir}, &out, &errb); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "metadata.name") {
		t.Errorf("stderr lacks validation errors: %q", errb.String())
	}
}

func TestInspectUsageAndMissing(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"inspect"}, &out, &errb); code != 2 {
		t.Errorf("no args: exit %d, want 2", code)
	}
	if code := run([]string{"inspect", filepath.Join(t.TempDir(), "nope")}, &out, &errb); code != 1 {
		t.Errorf("missing dir: exit %d, want 1", code)
	}
}

func TestInspectRejectsControlChars(t *testing.T) {
	src, err := os.ReadFile("testdata/pr-reviewer/capm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	y := strings.Replace(string(src), "Token used to read pull requests", `"a\nSecrets: none"`, 1)
	y = strings.Replace(y, "./workspace", `"./w\x1b[2J"`, 1)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "capm.yaml"), []byte(y), 0o644)
	var out, errb bytes.Buffer
	if code := run([]string{"inspect", dir}, &out, &errb); code != 1 {
		t.Fatalf("exit %d, want 1; stdout: %q", code, out.String())
	}
	if !strings.Contains(errb.String(), "control characters") || out.Len() != 0 {
		t.Errorf("stderr %q stdout %q", errb.String(), out.String())
	}
}

// C1: user-facing text must not claim signing or enforcement v1 lacks.
func TestUsageMakesNoSecurityOverclaims(t *testing.T) {
	var out, errb bytes.Buffer
	run([]string{"help"}, &out, &errb)
	run([]string{"inspect"}, &out, &errb)
	s := strings.ToLower(out.String() + errb.String())
	for _, bad := range []string{"signature", "verify its", "enforced permission", "enforced summary", "guarantee"} {
		if strings.Contains(s, bad) {
			t.Errorf("usage claims %q:\n%s", bad, s)
		}
	}
	if !strings.Contains(out.String(), "Show the bundle's declared permissions") {
		t.Errorf("inspect usage line wrong:\n%s", out.String())
	}
}

// I2 defence in depth: inspect never writes bidi/C1 controls even if a
// manifest slipped past validation (here: an older registry bundle).
func TestInspectOutputHasNoUnsafeRunes(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"inspect", "testdata/pr-reviewer"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if strings.ContainsFunc(out.String(), func(r rune) bool { return r != '\n' && manifest.DisplaySafe(string(r)) != string(r) }) {
		t.Errorf("unsafe rune in output: %q", out.String())
	}
	for _, h := range []string{"api.anthropic.com", manifest.EgressEnforcementNotice} {
		if !strings.Contains(out.String(), h) {
			t.Errorf("inspect lacks %q:\n%s", h, out.String())
		}
	}
}
