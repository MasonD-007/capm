package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	hostAdded     = "evil.example.com"
	diffHeader    = "Changes since the version you last ran (0.1.0 -> 0.2.0)"
	plainFlagsRun = "--allow-unenforced-egress"
)

func addHost(y string) string {
	return strings.Replace(y, "egress: [api.github.com]", "egress: [api.github.com, "+hostAdded+"]", 1)
}

// diffHarness has 0.1.0 (baseline) and 0.2.0 (adds a host) published.
func diffHarness(t *testing.T, stdin string, tty bool) *runHarness {
	t.Helper()
	h := pinHarness(t, stdin, tty)
	h.reg.add("alice", "pr-reviewer", "0.2.0", fixtureTar(t, "0.2.0", addHost), false)
	return h
}

func ref(v string) string { return "alice/pr-reviewer@" + v }

func TestRunRecordsVersionDigestAndManifest(t *testing.T) {
	h := diffHarness(t, "", false)
	if code := h.runArgs("--yes", plainFlagsRun, ref("0.1.0")); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	r, ok := h.knownRecord(t)
	if !ok || r.LastRun == nil {
		t.Fatalf("nothing recorded: %+v", r)
	}
	if r.LastRun.Version != "0.1.0" || !strings.HasPrefix(r.LastRun.Digest, "sha256:") || r.LastRun.Manifest == nil ||
		r.LastRun.Manifest.Permissions.Egress[0] != "api.github.com" || r.LastRun.At.IsZero() {
		t.Errorf("lastRun %+v", r.LastRun)
	}
	if strings.Contains(h.out.String(), "Changes since") {
		t.Error("diff shown on a first run")
	}
}

func TestRunEscalatingUpgradeNeedsMoreThanYes(t *testing.T) {
	h := diffHarness(t, "", false)
	h.runArgs("--yes", plainFlagsRun, ref("0.1.0"))
	calls := h.runner.count()

	// Non-interactive --yes alone: refused, names the flag, diff is shown.
	if code := h.runArgs("--yes", plainFlagsRun, ref("0.2.0")); code != 1 {
		t.Fatalf("exit %d; stderr %s", code, h.errb.String())
	}
	if !strings.Contains(h.errb.String(), "--accept-permission-changes") {
		t.Errorf("refusal does not name the flag:\n%s", h.errb.String())
	}
	out := h.out.String()
	if !strings.Contains(out, diffHeader) || !strings.Contains(out, "+ "+hostAdded) {
		t.Errorf("diff not shown:\n%s", out)
	}
	if h.runner.count() != calls {
		t.Error("sbx ran")
	}
	if r, _ := h.knownRecord(t); r.LastRun.Version != "0.1.0" {
		t.Errorf("recorded a run that was refused: %+v", r.LastRun)
	}

	// Without --yes and without a TTY the message mentions both flags.
	h.runArgs(plainFlagsRun, ref("0.2.0"))
	if e := h.errb.String(); !strings.Contains(e, "--accept-permission-changes") {
		t.Errorf("stderr %s", e)
	}

	// With the flag it proceeds and records the new version.
	if code := h.runArgs("--yes", "--accept-permission-changes", plainFlagsRun, ref("0.2.0")); code != 0 {
		t.Fatalf("exit %d; stderr %s", code, h.errb.String())
	}
	if r, _ := h.knownRecord(t); r.LastRun.Version != "0.2.0" {
		t.Errorf("not recorded: %+v", r.LastRun)
	}
}

func TestRunEscalatingUpgradeStillPromptsOnTTYWithYes(t *testing.T) {
	h := diffHarness(t, "n\n", true)
	h.runArgs("--yes", plainFlagsRun, ref("0.1.0"))
	h.env.stdin = strings.NewReader("n\n")
	calls := h.runner.count()
	if code := h.runArgs("--yes", plainFlagsRun, ref("0.2.0")); code != 1 {
		t.Fatalf("exit %d; stderr %s", code, h.errb.String())
	}
	if !strings.Contains(h.out.String(), "Proceed?") || h.runner.count() != calls {
		t.Errorf("--yes skipped the prompt for an escalation:\n%s", h.out.String())
	}
	if r, _ := h.knownRecord(t); r.LastRun.Version != "0.1.0" {
		t.Errorf("declined run was recorded: %+v", r.LastRun)
	}
	// Answering yes proceeds.
	h.env.stdin = strings.NewReader("y\n")
	if code := h.runArgs("--yes", plainFlagsRun, ref("0.2.0")); code != 0 {
		t.Fatalf("exit %d; stderr %s", code, h.errb.String())
	}
	if r, _ := h.knownRecord(t); r.LastRun.Version != "0.2.0" {
		t.Errorf("not recorded: %+v", r.LastRun)
	}
}

func TestRunDowngradeRemovedOnlyIsInformational(t *testing.T) {
	h := diffHarness(t, "", false)
	h.runArgs("--yes", plainFlagsRun, ref("0.2.0")) // first run: no diff, nothing to refuse
	if code := h.runArgs("--yes", plainFlagsRun, ref("0.1.0")); code != 0 {
		t.Fatalf("exit %d; stderr %s", code, h.errb.String())
	}
	out := h.out.String()
	if !strings.Contains(out, "Changes since the version you last ran (0.2.0 -> 0.1.0)") || !strings.Contains(out, "- "+hostAdded) {
		t.Errorf("downgrade diff missing:\n%s", out)
	}
}

func TestRunNoPermissionChangeIsQuiet(t *testing.T) {
	h := diffHarness(t, "", false)
	h.reg.add("alice", "pr-reviewer", "0.3.0", fixtureTar(t, "0.3.0", nil), false)
	h.runArgs("--yes", plainFlagsRun, ref("0.1.0"))
	if code := h.runArgs("--yes", plainFlagsRun, ref("0.3.0")); code != 0 {
		t.Fatalf("exit %d; stderr %s", code, h.errb.String())
	}
	if !strings.Contains(h.out.String(), "Changes since the version you last ran (0.1.0 -> 0.3.0): no permission changes") {
		t.Errorf("out:\n%s", h.out.String())
	}
}

func TestRunSameVersionDifferentDigestRefuses(t *testing.T) {
	h := diffHarness(t, "", false)
	h.runArgs("--yes", plainFlagsRun, ref("0.1.0"))
	old, _ := h.knownRecord(t)
	calls := h.runner.count()
	// The registry now serves other bytes under 0.1.0.
	h.reg.versions["alice/pr-reviewer@0.1.0"].tar = fixtureTar(t, "0.1.0", addHost)

	if code := h.runArgs("--yes", "--accept-permission-changes", plainFlagsRun, ref("0.1.0")); code != 1 {
		t.Fatalf("exit %d; stderr %s", code, h.errb.String())
	}
	e := h.errb.String()
	for _, want := range []string{"different bytes", "alice/pr-reviewer@0.1.0", old.LastRun.Digest, "--accept-changed-digest"} {
		if !strings.Contains(e, want) {
			t.Errorf("refusal lacks %q:\n%s", want, e)
		}
	}
	if h.runner.count() != calls {
		t.Error("sbx ran")
	}

	// --accept-changed-digest alone is not enough when the contents escalate.
	if code := h.runArgs("--yes", "--accept-changed-digest", plainFlagsRun, ref("0.1.0")); code != 1 {
		t.Fatalf("exit %d; stderr %s", code, h.errb.String())
	}
	if code := h.runArgs("--yes", "--accept-changed-digest", "--accept-permission-changes", plainFlagsRun, ref("0.1.0")); code != 0 {
		t.Fatalf("exit %d; stderr %s", code, h.errb.String())
	}
	if r, _ := h.knownRecord(t); r.LastRun.Digest == old.LastRun.Digest {
		t.Error("new digest not recorded")
	}
}

func TestInspectDiff(t *testing.T) {
	h := diffHarness(t, "", false)
	known := filepath.Join(h.env.credDir, "known.json")

	// Nothing recorded and no old version: say so, exit 0.
	if code := h.run("inspect", ref("0.2.0"), "--diff"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if !strings.Contains(h.out.String()+h.errb.String(), "nothing recorded") {
		t.Errorf("no explanation:\nout %s\nerr %s", h.out.String(), h.errb.String())
	}

	// Against an explicit old version fetched from the registry.
	if code := h.run("inspect", ref("0.2.0"), "--diff", "0.1.0"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if out := h.out.String(); !strings.Contains(out, "(0.1.0 -> 0.2.0)") || !strings.Contains(out, "+ "+hostAdded) {
		t.Errorf("diff:\n%s", out)
	}
	if _, err := os.Stat(known); err == nil {
		t.Fatal("inspect --diff wrote known.json")
	}

	// Against the recorded version.
	h.runArgs("--yes", plainFlagsRun, ref("0.1.0"))
	before, _ := os.ReadFile(known)
	if code := h.run("inspect", ref("0.2.0"), "--diff"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if out := h.out.String(); !strings.Contains(out, "(0.1.0 -> 0.2.0)") || !strings.Contains(out, "+ "+hostAdded) {
		t.Errorf("recorded diff:\n%s", out)
	}
	if after, _ := os.ReadFile(known); string(after) != string(before) {
		t.Error("inspect --diff modified known.json")
	}

	// Unknown old version is an error.
	if code := h.run("inspect", ref("0.2.0"), "--diff", "9.9.9"); code != 1 {
		t.Errorf("unknown old version: exit %d", code)
	}
}

func TestKnownListShowsLastRun(t *testing.T) {
	h := diffHarness(t, "", false)
	h.runArgs("--yes", plainFlagsRun, ref("0.1.0"))
	h.run("known")
	if !strings.Contains(h.out.String(), "0.1.0") {
		t.Errorf("table lacks last run version:\n%s", h.out.String())
	}
}
