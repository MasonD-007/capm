package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MasonD-007/capm/manifest"
)

func repoBundleTar(t *testing.T, repo string) []byte {
	t.Helper()
	dir := t.TempDir()
	meta := "{name: x, version: 1.0.0"
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

func inspectWith(t *testing.T, repo string, extra map[string]any) (code int, out, errs string) {
	t.Helper()
	h := newHarness(t)
	h.reg.add("alice", "x", "1.0.0", repoBundleTar(t, repo), false)
	h.reg.metaExtra = extra
	h.env.credDir = t.TempDir()
	code = h.run("inspect", "alice/x@1.0.0")
	return code, h.out.String(), h.errb.String()
}

func TestInspectShowsVerifiedProvenanceAsTheRegistrysStatement(t *testing.T) {
	code, out, errs := inspectWith(t, "https://github.com/alice/x", map[string]any{
		"repositoryVerified": true,
		"publishedVia": map[string]any{"repository": "alice/x", "sha": "0123456789abcdef0123456789abcdef01234567",
			"workflowRef": "alice/x/.github/workflows/publish.yml@refs/heads/main"},
	})
	if code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	for _, want := range []string{"registry says", "published from alice/x by a GitHub Actions workflow", "commit 0123456", "capm has not checked this"} {
		if !strings.Contains(errs, want) {
			t.Errorf("stderr lacks %q:\n%s", want, errs)
		}
	}
	if strings.Contains(errs, "not verified") || strings.Contains(out, "Published from") {
		t.Errorf("unverified wording or output on stdout:\n%s\n%s", errs, out)
	}
	low := strings.ToLower(errs + out)
	for _, bad := range []string{"safe", "trusted", "contents match", "matches the repository"} {
		if strings.Contains(low, bad) {
			t.Errorf("provenance line implies %q:\n%s", bad, errs)
		}
	}
}

func TestInspectShowsAnUnverifiedClaimAsAClaim(t *testing.T) {
	_, _, errs := inspectWith(t, "https://github.com/alice/x", nil)
	if !strings.Contains(errs, "repository (author's claim, not verified): https://github.com/alice/x") {
		t.Fatalf("%s", errs)
	}
	if strings.Contains(errs, "published from") {
		t.Fatalf("%s", errs)
	}
}

// The CLI cannot verify anything itself, but it will not print a "published
// from" line the manifest and the registry's own record do not agree on.
func TestInspectDowngradesAVerifiedClaimThatIsInconsistent(t *testing.T) {
	via := map[string]any{"repository": "mallory/other", "sha": "abc", "workflowRef": "x"}
	for name, c := range map[string]struct {
		repo  string
		extra map[string]any
	}{
		"CI repository differs from the manifest": {"https://github.com/alice/x", map[string]any{"repositoryVerified": true, "publishedVia": via}},
		"no provenance record":                    {"https://github.com/alice/x", map[string]any{"repositoryVerified": true}},
		"manifest names no repository":            {"", map[string]any{"repositoryVerified": true, "publishedVia": map[string]any{"repository": "alice/x"}}},
	} {
		_, _, errs := inspectWith(t, c.repo, c.extra)
		if strings.Contains(errs, "published from") {
			t.Errorf("%s: %s", name, errs)
		}
		if c.repo != "" && !strings.Contains(errs, "not verified") {
			t.Errorf("%s: claim not shown as unverified:\n%s", name, errs)
		}
	}
}

func TestInspectWithoutAnyRepositoryPrintsNothingAboutIt(t *testing.T) {
	_, out, errs := inspectWith(t, "", nil)
	if strings.Contains(strings.ToLower(out+errs), "repository") || strings.Contains(out+errs, "published from") {
		t.Fatalf("%s\n%s", out, errs)
	}
}

func TestInspectShowsWhoPublishedForAnOrganisationAndSanitises(t *testing.T) {
	_, _, errs := inspectWith(t, "", map[string]any{"ownerKind": "org", "publishedBy": "bo\x1b[31mb"})
	if !strings.Contains(errs, "published by bo[31mb (the registry's statement)") || strings.Contains(errs, "\x1b") {
		t.Fatalf("%q", errs)
	}
	_, _, errs = inspectWith(t, "https://github.com/alice/x", map[string]any{"repositoryVerified": true,
		"publishedVia": map[string]any{"repository": "alice/x", "sha": "ab\x1b[2Jcdef12345", "workflowRef": "w\u202eg"}})
	if strings.Contains(errs, "\x1b") || strings.Contains(errs, "\u202e") {
		t.Fatalf("%q", errs)
	}
}
