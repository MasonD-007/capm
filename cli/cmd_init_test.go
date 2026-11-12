package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/MasonD-007/capm/manifest"
)

// initHarness drives capm init with a fake stdin; tty says whether it looks
// like a terminal.
func initHarness(t *testing.T, tty bool, stdin string) *harness {
	h := newHarness(t)
	h.env.stdin = strings.NewReader(stdin)
	h.env.isTTY = func() bool { return tty }
	return h
}

func loadDir(t *testing.T, dir string) *manifest.Manifest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "capm.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := manifest.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, raw)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("validate: %v\n%s", err, raw)
	}
	return m
}

func listTree(t *testing.T, dir string) []string {
	var out []string
	filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && p != dir {
			rel, _ := filepath.Rel(dir, p)
			out = append(out, rel)
		}
		return nil
	})
	return out
}

func TestInitInteractiveHappyPath(t *testing.T) {
	answers := strings.Join([]string{
		"my-agent",                  // name
		"Does: things # with \"q\"", // description
		"alice, bob",                // authors
		"1",                         // base agent
		"",                          // base version (default)
		"Bad_Host.com",              // invalid egress: re-prompt
		"api.github.com, example.com",
		"./workspace", "2", // mount, read-write
		"", // no more mounts
		"GITHUB_TOKEN",
		"gh", "http://insecure.example.com", "https://mcp.example.com/mcp", "GITHUB_TOKEN",
		"", // no more MCP servers
		"", // starter prompt: default yes
	}, "\n") + "\n"
	h := initHarness(t, true, answers)
	dir := filepath.Join(t.TempDir(), "newdir", "bundle")
	if code := h.run("init", dir); code != 0 {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, h.out.String(), h.errb.String())
	}
	out := h.out.String()
	for _, want := range []string{"Bundle name [bundle]:", "1) claude-code", "2) opencode", "is not a valid host", "warning: read-write", "URL must be an https URL", "capm lint", "capm inspect .", "capm login", "capm push ."} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q:\n%s", want, out)
		}
	}
	m := loadDir(t, dir)
	if m.Metadata.Name != "my-agent" || m.Metadata.Version != "0.1.0" || m.Metadata.Description != "Does: things # with \"q\"" ||
		!reflect.DeepEqual(m.Metadata.Authors, []string{"alice", "bob"}) || m.Base.Agent != "claude-code" || m.Base.Version != defaultBaseVersion {
		t.Errorf("metadata/base: %+v %+v", m.Metadata, m.Base)
	}
	if !reflect.DeepEqual(m.Permissions.Egress, []string{"api.github.com", "example.com"}) ||
		!reflect.DeepEqual(m.Permissions.Mounts, []manifest.Mount{{Path: "./workspace", Mode: "read-write"}}) ||
		len(m.Secrets) != 1 || m.Secrets[0].Name != "GITHUB_TOKEN" ||
		!reflect.DeepEqual(m.MCP, []manifest.MCP{{Name: "gh", URL: "https://mcp.example.com/mcp", Secret: "GITHUB_TOKEN"}}) ||
		!reflect.DeepEqual(m.Context, []string{"prompts/system.md"}) {
		t.Errorf("sections: %+v", m)
	}
	for p, mode := range map[string]os.FileMode{"capm.yaml": 0o644, "prompts/system.md": 0o644, "prompts": 0o755, ".": 0o755} {
		st, err := os.Stat(filepath.Join(dir, p))
		if err != nil || st.Mode().Perm() != mode {
			t.Errorf("%s: %v %v", p, st, err)
		}
	}
	data, _ := os.ReadFile(filepath.Join(dir, "prompts/system.md"))
	if n := strings.Count(strings.TrimSpace(string(data)), "\n") + 1; n > 3 {
		t.Errorf("placeholder is %d lines", n)
	}
	// The generated directory is lint-clean even with a read-write mount.
	if code := h.run("lint", "--offline", "--strict", dir); code != 0 {
		t.Errorf("lint: %d\n%s", code, h.errb.String())
	}
}

func TestInitCommentsSurvive(t *testing.T) {
	h := initHarness(t, false, "")
	dir := t.TempDir()
	if code := h.run("init", "--yes", "--name", "demo", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "capm.yaml"))
	for _, section := range []string{"metadata:", "base:", "interface:", "model:", "permissions:", "secrets:", "mcp:", "context:"} {
		i := strings.Index("\n"+string(raw), "\n"+section)
		if i < 0 {
			t.Errorf("section %s missing", section)
			continue
		}
		before := strings.Split(strings.TrimRight(("\n" + string(raw))[:i], "\n"), "\n")
		if last := before[len(before)-1]; !strings.HasPrefix(last, "#") {
			t.Errorf("no comment directly above %s (got %q)", section, last)
		}
	}
}

func TestInitRefusesExistingManifest(t *testing.T) {
	h := initHarness(t, false, "")
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "capm.yaml"), []byte("mine"), 0o644)
	if code := h.run("init", "--yes", dir); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.errb.String(), "already exists") {
		t.Errorf("stderr %q", h.errb.String())
	}
	if got := listTree(t, dir); !reflect.DeepEqual(got, []string{"capm.yaml"}) {
		t.Errorf("tree %v", got)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "capm.yaml")); string(b) != "mine" {
		t.Error("manifest was modified")
	}
	// Also when interactive: refused before any question.
	h2 := initHarness(t, true, "x\n")
	if code := h2.run("init", dir); code != 1 || strings.Contains(h2.out.String(), "Bundle name") {
		t.Errorf("interactive: %d %q", code, h2.out.String())
	}
}

func TestInitNeverOverwritesPrompt(t *testing.T) {
	h := initHarness(t, false, "")
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "prompts"), 0o755)
	os.WriteFile(filepath.Join(dir, "prompts/system.md"), []byte("keep me"), 0o644)
	if code := h.run("init", "--yes", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "prompts/system.md")); string(b) != "keep me" {
		t.Errorf("prompt overwritten: %q", b)
	}
	loadDir(t, dir)
}

func TestInitNonInteractiveFlags(t *testing.T) {
	h := initHarness(t, false, "")
	dir := filepath.Join(t.TempDir(), "x")
	code := h.run("init", "--yes", "--name", "pr-bot", "--description", "Reviews PRs", "--author", "me", "--base", "opencode",
		"--egress", "api.github.com", "--egress", "example.com", "--mount", "./src:read-only", "--mount", "out:read-write",
		"--mount", "docs", "--secret", "GITHUB_TOKEN", "--secret", "OTHER", dir)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	m := loadDir(t, dir)
	if m.Metadata.Name != "pr-bot" || m.Base.Agent != "opencode" || m.Base.Version == "" ||
		!reflect.DeepEqual(m.Permissions.Egress, []string{"api.github.com", "example.com"}) ||
		!reflect.DeepEqual(m.Permissions.Mounts, []manifest.Mount{{Path: "./src", Mode: "read-only"}, {Path: "out", Mode: "read-write"}, {Path: "docs", Mode: "read-only"}}) ||
		len(m.Secrets) != 2 || len(m.MCP) != 0 {
		t.Errorf("manifest %+v", m)
	}
	if strings.Contains(h.out.String(), "Bundle name") {
		t.Error("--yes must not ask questions")
	}
	if code := h.run("lint", "--offline", "--strict", dir); code != 0 {
		t.Errorf("lint %d: %s", code, h.errb.String())
	}
}

func TestInitYesSkipsQuestionsOnTerminal(t *testing.T) {
	h := initHarness(t, true, "")
	dir := t.TempDir()
	if code := h.run("init", "-y", dir); code != 0 || strings.Contains(h.out.String(), "Bundle name") {
		t.Fatalf("exit %d %q", code, h.out.String())
	}
}

func TestInitRequiresYesWithoutTerminal(t *testing.T) {
	h := initHarness(t, false, "name\n")
	dir := filepath.Join(t.TempDir(), "never")
	if code := h.run("init", dir); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.errb.String(), "--yes") {
		t.Errorf("stderr %q", h.errb.String())
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("directory was created")
	}
}

func TestInitInvalidFlagsAreUsageErrors(t *testing.T) {
	bad := [][]string{
		{"--name", "Bad Name"}, {"--name", "-x"}, {"--base", "gpt"}, {"--egress", "Example.com"}, {"--egress", "*.example.com"},
		{"--egress", "10.0.0.1"}, {"--mount", "/etc:read-only"}, {"--mount", "../x"}, {"--mount", "a:rw"}, {"--secret", "lower"},
		{"--secret", "1A"}, {"--description", "a\nb"}, {"--author", ""}, {"--base-version", "has space"}, {"--bogus"},
	}
	for _, flags := range bad {
		h := initHarness(t, false, "")
		dir := filepath.Join(t.TempDir(), "d")
		args := append(append([]string{"init", "--yes"}, flags...), dir)
		if code := h.run(args...); code != 2 {
			t.Errorf("%v: exit %d (%s)", flags, code, h.errb.String())
		}
		if _, err := os.Stat(dir); err == nil {
			t.Errorf("%v: wrote something", flags)
		}
	}
	h := initHarness(t, false, "")
	if code := h.run("init", "--yes", "a", "b"); code != 2 {
		t.Errorf("two dirs: %d", code)
	}
}

func TestInitDefaultName(t *testing.T) {
	cases := map[string]string{"My_Cool Agent": "my-cool-agent", "demo": "demo", "---": "my-bundle", "UPPER": "upper", "a..b": "a-b", strings.Repeat("a", 80): strings.Repeat("a", 64)}
	for dirName, want := range cases {
		dir := filepath.Join(t.TempDir(), dirName)
		if got := defaultBundleName(dir); got != want {
			t.Errorf("%q -> %q want %q", dirName, got, want)
		}
		h := initHarness(t, false, "")
		if code := h.run("init", "--yes", dir); code != 0 {
			t.Errorf("%q: exit %d %s", dirName, code, h.errb.String())
			continue
		}
		if loadDir(t, dir).Metadata.Name != want {
			t.Errorf("%q: name in file", dirName)
		}
	}
}

func TestInitInteractiveEndOfInputWritesNothing(t *testing.T) {
	h := initHarness(t, true, "partial\n")
	dir := filepath.Join(t.TempDir(), "d")
	if code := h.run("init", dir); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Error("directory created")
	}
}

func TestInitInteractiveOpencodeAndNoPrompt(t *testing.T) {
	// name default, no description/authors, base by name, version default,
	// no egress/mounts/secrets/mcp, no starter prompt.
	h := initHarness(t, true, strings.Repeat("\n", 2)+"\nopencode\n\n\n\n\n\nn\n")
	dir := filepath.Join(t.TempDir(), "oc")
	if code := h.run("init", dir); code != 0 {
		t.Fatalf("exit %d\n%s\n%s", code, h.out.String(), h.errb.String())
	}
	m := loadDir(t, dir)
	if m.Base.Agent != "opencode" || m.Base.Version != fallbackBaseVersion || len(m.Context) != 0 || m.Metadata.Name != "oc" {
		t.Errorf("%+v", m)
	}
	if _, err := os.Stat(filepath.Join(dir, "prompts")); err == nil {
		t.Error("prompts dir created although declined")
	}
}

// What a freshly generated bundle still reports: only the two rules about
// text the author has not written yet.
func TestInitGeneratedBundlesLint(t *testing.T) {
	complete := []string{"--description", "d", "--author", "a"}
	combos := [][]string{
		{},
		{"--egress", "api.github.com"},
		{"--mount", "work:read-write"},
		{"--mount", "work:read-only", "--secret", "TOKEN", "--base", "opencode"},
		{"--egress", "a.example.com", "--egress", "b.example.com", "--mount", "x:read-write", "--mount", "y", "--secret", "A_B", "--secret", "C"},
		{"--description", `tricky: "quotes" # and 'apostrophes' \ backslash`},
	}
	for _, c := range combos {
		for _, withText := range []bool{false, true} {
			args := append([]string{"init", "--yes", "--name", "demo"}, c...)
			if withText {
				args = append(args, complete...)
			}
			h := initHarness(t, false, "")
			dir := filepath.Join(t.TempDir(), "demo")
			if code := h.run(append(args, dir)...); code != 0 {
				t.Fatalf("%v: init exit %d: %s", args, code, h.errb.String())
			}
			loadDir(t, dir)
			code := h.run("lint", "--offline", dir)
			s := h.errb.String()
			if code != 0 || strings.Contains(s, "error[") {
				t.Errorf("%v: lint exit %d\n%s", args, code, s)
			}
			hasDesc := withText || containsArg(c, "--description")
			wantWarn := map[string]bool{}
			if !hasDesc {
				wantWarn["no_description"] = true
			}
			if !withText {
				wantWarn["no_authors"] = true
			}
			for _, id := range []string{"no_description", "no_authors", "context_unlisted", "context_missing", "secret_file", "secret_file_nearby", "size_near_limit", "version_not_bumped"} {
				if got := strings.Contains(s, "["+id+"]"); got != wantWarn[id] {
					t.Errorf("%v: rule %s fired=%v want %v\n%s", args, id, got, wantWarn[id], s)
				}
			}
			strict := h.run("lint", "--offline", "--strict", dir)
			if (strict == 0) != (len(wantWarn) == 0) {
				t.Errorf("%v: strict exit %d with %d expected warnings", args, strict, len(wantWarn))
			}
		}
	}
}

func containsArg(args []string, a string) bool { return contains(args, a) }
