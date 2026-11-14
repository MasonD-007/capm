package main

import (
	"os"
	"strings"
	"testing"

	"github.com/MasonD-007/capm/manifest"
)

// The signature binds bytes, not owner/name@version, and the registry is
// untrusted: whatever it serves must say, inside the tarball, that it is the
// bundle and version that were asked for.

func TestPullRefusesManifestNameMismatch(t *testing.T) {
	h := newHarness(t)
	root := chdirTemp(t)
	h.reg.add("bob", "agent", "1.0.0", testBundleTar(t, "other", "1.0.0"), false)
	if code := h.run("pull", "bob/agent@1.0.0"); code != 1 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if !strings.Contains(h.errb.String(), "says it is other@1.0.0") {
		t.Errorf("stderr: %q", h.errb.String())
	}
	if ents, _ := os.ReadDir("."); len(ents) != 0 {
		t.Errorf("cwd not clean: %v", ents)
	}
	_ = root
	if _, err := os.Stat(h.env.credDir + "/known.json"); err == nil {
		t.Error("a refused pull recorded state")
	}
}

func TestPullRefusesManifestVersionMismatch(t *testing.T) {
	h := newHarness(t)
	chdirTemp(t)
	h.reg.add("bob", "agent", "1.1.0", testBundleTar(t, "agent", "1.0.0"), false)
	if code := h.run("pull", "bob/agent@1.1.0"); code != 1 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if !strings.Contains(h.errb.String(), "says it is agent@1.0.0") || !strings.Contains(h.errb.String(), "bob/agent@1.1.0") {
		t.Errorf("stderr: %q", h.errb.String())
	}
	if _, err := os.Stat("agent"); err == nil {
		t.Error("bundle was unpacked")
	}
}

func TestPullLatestChecksResolvedVersion(t *testing.T) {
	h := newHarness(t)
	chdirTemp(t)
	h.reg.add("bob", "agent", "2.0.0", testBundleTar(t, "agent", "1.0.0"), false)
	if code := h.run("pull", "bob/agent"); code != 1 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
}

func TestPullAcceptsMatchingManifest(t *testing.T) {
	h := newHarness(t)
	chdirTemp(t)
	h.reg.add("bob", "agent", "1.0.0", testBundleTar(t, "agent", "1.0.0"), false)
	if code := h.run("pull", "bob/agent@1.0.0"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
}

func TestRunRefusesManifestMismatch(t *testing.T) {
	for _, tc := range []struct{ name, version string }{{"other", "0.1.0"}, {"pr-reviewer", "0.2.0"}} {
		t.Run(strings.ReplaceAll(tc.name+"-"+tc.version, ".", "_"), func(t *testing.T) {
			h := newRunHarness(t, "", false)
			dir := testBundleDir(t, tc.name, tc.version)
			tarball, err := manifest.PackDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			h.reg.add("alice", "pr-reviewer", "0.1.0", tarball, false)
			if code := h.runArgs("--yes", "--allow-unenforced-egress", "alice/pr-reviewer@0.1.0"); code != 1 {
				t.Fatalf("exit %d: %s", code, h.errb.String())
			}
			if !strings.Contains(h.errb.String(), "says it is") {
				t.Errorf("stderr: %q", h.errb.String())
			}
			if h.runner.count() != 0 {
				t.Error("sbx was invoked")
			}
			h.assertNoLeaks(t)
		})
	}
}
