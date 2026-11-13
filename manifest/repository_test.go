package manifest

import (
	"strings"
	"testing"
)

func TestParseRepository(t *testing.T) {
	long := strings.Repeat("a", 101)
	tests := []struct {
		in          string
		owner, repo string
		ok          bool
	}{
		{"https://github.com/MasonD-007/capm", "MasonD-007", "capm", true},
		{"https://github.com/a/b", "a", "b", true},
		{"https://github.com/acme/my.repo_name-2", "acme", "my.repo_name-2", true},
		{"https://github.com/acme/.github", "acme", ".github", true},
		{"https://github.com/acme/x.github.io", "acme", "x.github.io", true},
		// shape violations
		{"", "", "", false},
		{"http://github.com/a/b", "", "", false},
		{"HTTPS://github.com/a/b", "", "", false},
		{"https://GitHub.com/a/b", "", "", false},
		{"https://www.github.com/a/b", "", "", false},
		{"https://github.com.evil.example/a/b", "", "", false},
		{"https://github.com@evil.example/a/b", "", "", false},
		{"https://user@github.com/a/b", "", "", false},
		{"https://user:pw@github.com/a/b", "", "", false},
		{"https://github.com:443/a/b", "", "", false},
		{"https://gitlab.com/a/b", "", "", false},
		{"https://github.com/a/b/", "", "", false},
		{"https://github.com/a/b.git", "", "", false},
		{"https://github.com/a/b/tree/main", "", "", false},
		{"https://github.com/a", "", "", false},
		{"https://github.com/", "", "", false},
		{"https://github.com//b", "", "", false},
		{"https://github.com/a//b", "", "", false},
		{"https://github.com/a/b?x=1", "", "", false},
		{"https://github.com/a/b#readme", "", "", false},
		{"https://github.com/a/b%2Fc", "", "", false},
		{"https://github.com/a b/c", "", "", false},
		{"https://github.com/-a/b", "", "", false},
		{"https://github.com/a_b/c", "", "", false},
		{"https://github.com/" + strings.Repeat("a", 40) + "/b", "", "", false},
		{"https://github.com/a/" + long, "", "", false},
		{"https://github.com/a/.", "", "", false},
		{"https://github.com/a/..", "", "", false},
		{"https://github.com/a/b\n", "", "", false},
		{"https://github.com/a/b\x00", "", "", false},
		{"https://github.com/a/b ", "", "", false},
		{" https://github.com/a/b", "", "", false},
		{"https://github.com/а/b", "", "", false}, // Cyrillic a
		{"https://gıthub.com/a/b", "", "", false}, // dotless i look-alike host
		{"https://github.com/a/b​", "", "", false},
		{"javascript:alert(1)", "", "", false},
		{"data:text/html,x", "", "", false},
	}
	for _, c := range tests {
		owner, repo, ok := ParseRepository(c.in)
		if ok != c.ok || owner != c.owner || repo != c.repo {
			t.Errorf("ParseRepository(%q) = %q, %q, %v; want %q, %q, %v", c.in, owner, repo, ok, c.owner, c.repo, c.ok)
		}
	}
}

func TestRepositoryMatches(t *testing.T) {
	tests := []struct {
		claim, ci string
		want      bool
	}{
		{"https://github.com/alice/x", "alice/x", true},
		{"https://github.com/Alice/X", "alice/x", true}, // case-insensitive
		{"https://github.com/alice/x", "ALICE/X", true},
		{"https://github.com/alice/x", "alice/y", false},
		{"https://github.com/bob/x", "alice/x", false},
		{"https://github.com/alice/x/", "alice/x", false}, // trailing slash
		{"https://github.com/alice/x.git", "alice/x", false},
		{"https://github.com/alice/x/extra", "alice/x", false},
		{"https://gitlab.com/alice/x", "alice/x", false},
		{"http://github.com/alice/x", "alice/x", false},
		{"https://github.com/alice/x", "alice/x/extra", false},
		{"https://github.com/alice/x", "alice", false},
		{"https://github.com/alice/x", "alice/", false},
		{"https://github.com/alice/x", "/x", false},
		{"https://github.com/alice/x", "", false},
		{"", "alice/x", false},
		{"", "", false},
		{"https://github.com/alice/x", "alice/x ", false},
		{"https://github.com/alice/x", "https://github.com/alice/x", false},
		{"https://github.com/alice/x", "alice/x.git", false},
	}
	for _, c := range tests {
		if got := RepositoryMatches(c.claim, c.ci); got != c.want {
			t.Errorf("RepositoryMatches(%q, %q) = %v, want %v", c.claim, c.ci, got, c.want)
		}
	}
}

func TestValidateRepository(t *testing.T) {
	good := validManifest()
	good.Metadata.Repository = "https://github.com/MasonD-007/capm"
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"https://github.com/a/b/", "https://github.com/a/b.git", "http://github.com/a/b",
		"https://gitlab.com/a/b", "https://github.com/a/b?x", "https://github.com/a/b\n", "github.com/a/b", "https://github.com/a"} {
		m := validManifest()
		m.Metadata.Repository = bad
		err := m.Validate()
		if err == nil || !strings.Contains(err.Error(), "metadata.repository") {
			t.Errorf("%q: %v", bad, err)
		}
	}
	// Absent is fine, and is the common case.
	m := validManifest()
	m.Metadata.Repository = ""
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRepositoryParsesFromYAMLAndRoundTrips(t *testing.T) {
	y := "apiVersion: capm/v0\nkind: Agent\nmetadata: {name: x, version: 1.0.0, repository: \"https://github.com/alice/x\"}\n" +
		"base: {agent: claude-code, version: 1}\ninterface: {type: tty}\nmodel: {api: a, requires: {toolCalling: true, minContextTokens: 1}}\n"
	m, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	if m.Metadata.Repository != "https://github.com/alice/x" {
		t.Fatalf("%q", m.Metadata.Repository)
	}
}
