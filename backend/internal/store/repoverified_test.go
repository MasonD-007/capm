package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/MasonD-007/capm/manifest"
)

func bundleRepo(t *testing.T, name, version, repo string) []byte {
	t.Helper()
	dir := t.TempDir()
	meta := "{name: " + name + ", version: " + version
	if repo != "" {
		meta += ", repository: \"" + repo + "\""
	}
	y := "apiVersion: capm/v0\nkind: Agent\nmetadata: " + meta + "}\n" +
		"base: {agent: claude-code, version: 2.1.292}\ninterface: {type: tty}\n" +
		"model: {api: openai-compatible, requires: {toolCalling: true, minContextTokens: 1000}}\n"
	if err := os.WriteFile(filepath.Join(dir, manifest.FileName), []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := manifest.PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRepoVerifiedOnlyForACIPublishWhoseClaimMatchesStructurally(t *testing.T) {
	ciVia := func(repo string) string { return `{"repository":"` + repo + `","repository_id":"7","sha":"abc"}` }
	cases := []struct {
		name     string
		manifest string // metadata.repository ("" = none)
		via      string // provenance of a CI token ("" = interactive publish)
		want     bool
	}{
		{"CI repo equals manifest", "https://github.com/alice/x", ciVia("alice/x"), true},
		{"different case still matches", "https://github.com/Alice/X", ciVia("alice/x"), true},
		{"interactive publish is never verified", "https://github.com/alice/x", "", false},
		{"manifest without repository", "", ciVia("alice/x"), false},
		{"different repo", "https://github.com/alice/other", ciVia("alice/x"), false},
		{"different owner", "https://github.com/mallory/x", ciVia("alice/x"), false},
		{"CI claim malformed", "https://github.com/alice/x", ciVia("alice/x/extra"), false},
		{"CI claim empty", "https://github.com/alice/x", ciVia(""), false},
		{"provenance without repository", "https://github.com/alice/x", `{"sha":"abc"}`, false},
		{"provenance that is not JSON", "https://github.com/alice/x", `not json`, false},
	}
	for i, c := range cases {
		s, _ := openClock(t)
		s.UpsertUser(42, "alice")
		v := "1.0." + string(rune('0'+i%10))
		if err := s.PublishVia(42, "alice", "x", v, bundleRepo(t, "x", v, c.manifest), c.via); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		vs, err := s.Versions("alice", "x")
		if err != nil || len(vs) != 1 {
			t.Fatalf("%s: %v %v", c.name, vs, err)
		}
		if vs[0].RepoVerified != c.want {
			t.Errorf("%s: RepoVerified = %v, want %v", c.name, vs[0].RepoVerified, c.want)
		}
	}
}

// A manifest naming a repository that is not exactly a github.com URL is
// refused at publish: there is no such thing as a verified look-alike.
func TestPublishRefusesALookAlikeRepository(t *testing.T) {
	for _, repo := range []string{"https://github.com/alice/x/", "https://github.com/alice/x.git",
		"https://gitlab.com/alice/x", "http://github.com/alice/x", "https://github.com/alice/x/tree/main"} {
		s, _ := openClock(t)
		y := "apiVersion: capm/v0\nkind: Agent\nmetadata: {name: x, version: 1.0.0, repository: \"" + repo + "\"}\n" +
			"base: {agent: claude-code, version: 2.1.292}\ninterface: {type: tty}\n" +
			"model: {api: openai-compatible, requires: {toolCalling: true, minContextTokens: 1000}}\n"
		tb := rawTar(t, map[string]string{"capm.yaml": y}, []string{"capm.yaml"}) // bypasses the client-side check
		err := s.PublishVia(42, "alice", "x", "1.0.0", tb, `{"repository":"alice/x"}`)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", repo, err)
		}
	}
}
