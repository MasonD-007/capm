package manifest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func findingIDs(fs []Finding) []string {
	out := []string{}
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

func TestLintRules(t *testing.T) {
	m := validManifest()
	if got := m.Lint(); len(got) != 0 {
		t.Fatalf("complete manifest has findings: %v", got)
	}
	m.Metadata.Description = ""
	if got := findingIDs(m.Lint()); !reflect.DeepEqual(got, []string{"no_description"}) {
		t.Errorf("no description: %v", got)
	}
	m.Metadata.Authors = nil
	got := m.Lint()
	if !reflect.DeepEqual(findingIDs(got), []string{"no_description", "no_authors"}) {
		t.Errorf("both: %v", findingIDs(got))
	}
	for _, f := range got {
		if f.Severity != LintWarning || f.Message == "" {
			t.Errorf("bad finding %+v", f)
		}
	}
	m.Metadata.Description = "  \t"
	if got := findingIDs(m.Lint()); !reflect.DeepEqual(got, []string{"no_description", "no_authors"}) {
		t.Errorf("blank description should count as empty: %v", got)
	}
}

func TestCompareVersions(t *testing.T) {
	order := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
		"1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.9.0", "1.10.0", "2.0.0"}
	for i := range order {
		for j := range order {
			c, ok := CompareVersions(order[i], order[j])
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if !ok || c != want {
				t.Errorf("%s vs %s = %d,%v want %d", order[i], order[j], c, ok, want)
			}
		}
	}
	if c, ok := CompareVersions("1.0.0+a", "1.0.0+b"); !ok || c != 0 {
		t.Errorf("build metadata must be ignored: %d %v", c, ok)
	}
	for _, bad := range []string{"1.0", "v1.0.0", "01.0.0", "1.0.0-", "a.b.c", ""} {
		if _, ok := CompareVersions(bad, "1.0.0"); ok {
			t.Errorf("%q should not compare", bad)
		}
	}
}

func TestValidHelpersAgreeWithValidate(t *testing.T) {
	hosts := map[string]bool{"api.github.com": true, "localhost": true, "Example.com": false, "1.2.3.4": false, "a_b.com": false, "": false, "*.x.com": false}
	for h, want := range hosts {
		if got := ValidHost(h); got != want {
			t.Errorf("ValidHost(%q)=%v want %v", h, got, want)
		}
		m := validManifest()
		m.Permissions.Egress = []string{h}
		if (m.Validate() == nil) != want {
			t.Errorf("Validate disagrees on host %q", h)
		}
	}
	if !ValidName("demo-1") || ValidName("Demo") || ValidName("-a") || ValidName("") {
		t.Error("ValidName")
	}
	if !ValidSecretName("GITHUB_TOKEN") || ValidSecretName("github") || ValidSecretName("1A") {
		t.Error("ValidSecretName")
	}
	if !ValidMountPath("./workspace") || !ValidMountPath("data") || ValidMountPath("/etc") || ValidMountPath("../x") || ValidMountPath("") {
		t.Error("ValidMountPath")
	}
	if len(BaseAgents) == 0 {
		t.Fatal("no base agents")
	}
	for _, a := range BaseAgents {
		m := validManifest()
		m.Base.Agent = a
		if err := m.Validate(); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
	m := validManifest()
	m.Base.Agent = "nope"
	if err := m.Validate(); err == nil || !strings.Contains(err.Error(), "must be claude-code or opencode") {
		t.Errorf("error text changed: %v", err)
	}
}

func tarNames(t *testing.T, tb []byte) []string {
	gz, err := gzip.NewReader(bytes.NewReader(tb))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var out []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, h.Name)
	}
}

func TestPackedFilesMatchPackDir(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "prompts"), 0o755)
	os.WriteFile(filepath.Join(dir, "capm.yaml"), []byte(`apiVersion: capm/v0
kind: Agent
metadata: {name: a, version: 1.0.0}
base: {agent: claude-code, version: 1.0.0}
interface: {type: tty}
model: {api: openai-compatible, requires: {toolCalling: true, minContextTokens: 1}}
context: [prompts/a.md, README.md, prompts/gone.md]
`), 0o644)
	os.WriteFile(filepath.Join(dir, "prompts/a.md"), []byte("hi"), 0o644)
	os.WriteFile(filepath.Join(dir, "README.md"), []byte("r"), 0o644)
	raw, _ := os.ReadFile(filepath.Join(dir, "capm.yaml"))
	m, _ := Parse(raw)
	files := PackedFiles(dir, m)
	var names []string
	bad := 0
	for _, f := range files {
		names = append(names, f.Name)
		if f.Err != nil {
			bad++
			if f.Name != "prompts/gone.md" {
				t.Errorf("unexpected error on %s: %v", f.Name, f.Err)
			}
		}
	}
	if !reflect.DeepEqual(names, []string{"capm.yaml", "README.md", "prompts/a.md", "prompts/gone.md"}) || bad != 1 {
		t.Fatalf("names %v bad %d", names, bad)
	}
	// Once the missing file is removed from the list, PackDir packs exactly these.
	os.WriteFile(filepath.Join(dir, "capm.yaml"), bytes.Replace(raw, []byte(", prompts/gone.md"), nil, 1), 0o644)
	tb, err := PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := tarNames(t, tb); !reflect.DeepEqual(got, []string{"capm.yaml", "README.md", "prompts/a.md"}) {
		t.Errorf("PackDir entries %v", got)
	}
	// A symlink README is not packed as the implicit README, and listing it
	// in context is an error.
	os.Remove(filepath.Join(dir, "README.md"))
	os.WriteFile(filepath.Join(dir, "other.md"), []byte("x"), 0o644)
	os.Symlink("other.md", filepath.Join(dir, "README.md"))
	raw, _ = os.ReadFile(filepath.Join(dir, "capm.yaml"))
	m, _ = Parse(raw)
	found := false
	for _, f := range PackedFiles(dir, m) {
		if f.Name == "README.md" {
			found = true
			if f.Err == nil {
				t.Errorf("symlink context README should error")
			}
		}
	}
	if !found {
		t.Error("README.md listed in context missing from PackedFiles")
	}
}
