package auth_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

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

type repoView struct {
	Repository         string `json:"repository"`
	RepositoryVerified *bool  `json:"repositoryVerified"`
}

func getJSON(t *testing.T, e *oidcEnv, path string, out any) {
	t.Helper()
	code, b := e.do(t, "GET", path, "", nil)
	if code != 200 {
		t.Fatalf("%s: %d %s", path, code, b)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("%s: %v %s", path, err, b)
	}
}

func TestRepositoryVerifiedIsTrueOnlyForAMatchingCIPublish(t *testing.T) {
	e := newOIDCEnv(t, 0)
	ci := ciToken(t, e) // repository alice/x
	e.st.UpsertUser(42, "alice")
	full := e.mint(t, "alice-full", "", time.Time{})

	pub := func(tok, name, version, repo string) {
		t.Helper()
		if code, b := e.do(t, "PUT", "/v1/bundles/alice/"+name+"/"+version, tok, bundleRepo(t, name, version, repo)); code != 201 {
			t.Fatalf("%s: %d %s", name, code, b)
		}
	}
	pub(ci, "match", "1.0.0", "https://github.com/alice/x")
	pub(ci, "case", "1.0.0", "https://github.com/ALICE/X")
	pub(ci, "otherrepo", "1.0.0", "https://github.com/alice/other")
	pub(ci, "otherowner", "1.0.0", "https://github.com/mallory/x")
	pub(ci, "norepo", "1.0.0", "")
	pub(full, "interactive", "1.0.0", "https://github.com/alice/x")

	want := map[string]struct {
		repo     string
		verified bool
	}{
		"match":       {"https://github.com/alice/x", true},
		"case":        {"https://github.com/ALICE/X", true},
		"otherrepo":   {"https://github.com/alice/other", false},
		"otherowner":  {"https://github.com/mallory/x", false},
		"norepo":      {"", false},
		"interactive": {"https://github.com/alice/x", false},
	}
	for name, w := range want {
		var meta repoView
		getJSON(t, e, "/v1/bundles/alice/"+name+"/1.0.0", &meta)
		if meta.Repository != w.repo || meta.RepositoryVerified == nil || *meta.RepositoryVerified != w.verified {
			t.Errorf("metadata %s: %+v, want %v/%v", name, meta, w.repo, w.verified)
		}
		var vs []repoView
		getJSON(t, e, "/v1/bundles/alice/"+name, &vs)
		if len(vs) != 1 || vs[0].Repository != w.repo || vs[0].RepositoryVerified == nil || *vs[0].RepositoryVerified != w.verified {
			t.Errorf("versions %s: %+v", name, vs)
		}
	}
	var list []struct {
		Name string `json:"name"`
		repoView
	}
	getJSON(t, e, "/v1/bundles?owner=alice", &list)
	if len(list) != len(want) {
		t.Fatalf("%d items", len(list))
	}
	for _, it := range list {
		w := want[it.Name]
		if it.Repository != w.repo || it.RepositoryVerified == nil || *it.RepositoryVerified != w.verified {
			t.Errorf("list %s: %+v", it.Name, it.repoView)
		}
	}
}

func TestOrgCIPublishVerifiesTheOrgsRepository(t *testing.T) {
	e := newOIDCEnv(t, 0)
	tok := orgCIToken(t, e, "acme", 77) // repository acme/x
	if code, b := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.0", tok, bundleRepo(t, "x", "1.0.0", "https://github.com/acme/x")); code != 201 {
		t.Fatalf("%d %s", code, b)
	}
	var meta struct {
		repoView
		OwnerKind   string `json:"ownerKind"`
		PublishedBy string `json:"publishedBy"`
	}
	getJSON(t, e, "/v1/bundles/acme/x/1.0.0", &meta)
	if meta.RepositoryVerified == nil || !*meta.RepositoryVerified || meta.OwnerKind != "org" || meta.PublishedBy != "" {
		t.Fatalf("%+v", meta)
	}
}
