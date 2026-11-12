package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MasonD-007/capm/manifest"
)

// fixtureTar packs a copy of the pr-reviewer fixture at the given version;
// edit (optional) rewrites the manifest text first.
func fixtureTar(t *testing.T, version string, edit func(string) string) []byte {
	t.Helper()
	dst := t.TempDir()
	if err := os.CopyFS(dst, os.DirFS(fixtureDir)); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dst, manifest.FileName)
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	y := strings.Replace(string(b), "version: 0.1.0", "version: "+version, 1)
	if edit != nil {
		y = edit(y)
	}
	if err := os.WriteFile(p, []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	tb, err := manifest.PackDir(dst)
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

// pinHarness is a run harness with the fixture published as alice/pr-reviewer
// 0.1.0 by owner id 7.
func pinHarness(t *testing.T, stdin string, tty bool) *runHarness {
	t.Helper()
	h := newRunHarness(t, stdin, tty)
	h.reg.add("alice", "pr-reviewer", "0.1.0", fixtureTar(t, "0.1.0", nil), false)
	h.reg.ownerID = 7
	chdirTemp(t)
	return h
}

func (h *runHarness) knownRecord(t *testing.T) (knownRecord, bool) {
	t.Helper()
	return newKnownStore(h.env, &strings.Builder{}).get(h.env.registry, "alice", "pr-reviewer")
}

const refTarget = "alice/pr-reviewer@0.1.0"

func TestRunFirstRunPinsOwner(t *testing.T) {
	h := pinHarness(t, "", false)
	if code := h.runArgs("--yes", "--allow-unenforced-egress", refTarget); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	r, ok := h.knownRecord(t)
	if !ok || r.OwnerID != 7 {
		t.Fatalf("record %+v ok=%v", r, ok)
	}
	// Same owner again: fine, still pinned.
	if code := h.runArgs("--yes", "--allow-unenforced-egress", refTarget); code != 0 {
		t.Fatalf("second run exit %d: %s", code, h.errb.String())
	}
	if strings.Contains(h.errb.String(), "pinning") {
		t.Errorf("unexpected pin chatter: %s", h.errb.String())
	}
}

func TestRunDeclinedDoesNotPin(t *testing.T) {
	h := pinHarness(t, "n\n", true)
	if code := h.runArgs("--allow-unenforced-egress", refTarget); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(h.env.credDir, "known.json")); err == nil {
		t.Error("state written although the user declined")
	}
}

func TestRunChangedOwnerRefuses(t *testing.T) {
	h := pinHarness(t, "", false)
	if code := h.runArgs("--yes", "--allow-unenforced-egress", refTarget); code != 0 {
		t.Fatalf("exit %d", code)
	}
	calls := h.runner.count()
	h.reg.ownerID = 99
	if code := h.runArgs("--yes", "--allow-unenforced-egress", refTarget); code != 1 {
		t.Fatalf("exit %d, want 1; stderr %s", code, h.errb.String())
	}
	e := h.errb.String()
	for _, want := range []string{"alice/pr-reviewer", "7", "99", "taken over", "different GitHub account", "--accept-new-owner"} {
		if !strings.Contains(e, want) {
			t.Errorf("refusal lacks %q:\n%s", want, e)
		}
	}
	if h.runner.count() != calls {
		t.Error("sbx ran for a bundle with a changed owner")
	}
	if strings.Contains(h.out.String(), "Proceed?") {
		t.Error("prompted before refusing")
	}
	if r, _ := h.knownRecord(t); r.OwnerID != 7 {
		t.Errorf("pin changed on refusal: %+v", r)
	}

	// The flag proceeds and re-pins.
	if code := h.runArgs("--yes", "--allow-unenforced-egress", "--accept-new-owner", refTarget); code != 0 {
		t.Fatalf("with flag: exit %d: %s", code, h.errb.String())
	}
	if r, _ := h.knownRecord(t); r.OwnerID != 99 {
		t.Errorf("not re-pinned: %+v", r)
	}
}

func TestRunServerWithoutOwnerIDWarnsOnceAndProceeds(t *testing.T) {
	h := pinHarness(t, "", false)
	h.reg.ownerID = 0
	if code := h.runArgs("--yes", "--allow-unenforced-egress", refTarget); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if n := strings.Count(h.errb.String(), "owner pinning is unavailable"); n != 1 {
		t.Errorf("warned %d times:\n%s", n, h.errb.String())
	}
	if r, ok := h.knownRecord(t); ok && r.OwnerID != 0 {
		t.Errorf("pinned without an id: %+v", r)
	}
}

func TestRunCorruptKnownFileWarnsAndProceeds(t *testing.T) {
	h := pinHarness(t, "", false)
	os.MkdirAll(h.env.credDir, 0o700)
	os.WriteFile(filepath.Join(h.env.credDir, "known.json"), []byte("garbage"), 0o600)
	if code := h.runArgs("--yes", "--allow-unenforced-egress", refTarget); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if n := strings.Count(h.errb.String(), "known.json"); n != 1 {
		t.Errorf("want one warning naming known.json, got %d:\n%s", n, h.errb.String())
	}
	if r, ok := h.knownRecord(t); !ok || r.OwnerID != 7 {
		t.Errorf("corrupt file not replaced: %+v", r)
	}
}

func TestRunLocalDirectoryIsNeverRecorded(t *testing.T) {
	abs, err := filepath.Abs(fixtureDir) // pinHarness changes directory
	if err != nil {
		t.Fatal(err)
	}
	h := pinHarness(t, "", false)
	if code := h.runArgs("--yes", "--allow-unenforced-egress", abs); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if _, err := os.Stat(filepath.Join(h.env.credDir, "known.json")); err == nil {
		t.Error("a local run wrote known.json")
	}
	if strings.Contains(h.errb.String(), "pinning") {
		t.Errorf("local run mentioned pinning: %s", h.errb.String())
	}
}

func TestPullPinsAndRefusesChangedOwner(t *testing.T) {
	h := pinHarness(t, "", false)
	if code := h.run("pull", refTarget); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if r, ok := h.knownRecord(t); !ok || r.OwnerID != 7 {
		t.Fatalf("pull did not pin: %+v", r)
	}
	os.RemoveAll("pr-reviewer")
	h.reg.ownerID = 99
	if code := h.run("pull", refTarget); code != 1 {
		t.Fatalf("exit %d; %s", code, h.errb.String())
	}
	if e := h.errb.String(); !strings.Contains(e, "99") || !strings.Contains(e, "--accept-new-owner") {
		t.Errorf("stderr %s", e)
	}
	if _, err := os.Stat("pr-reviewer"); err == nil {
		t.Error("bundle unpacked despite refusal")
	}
	if code := h.run("pull", "--accept-new-owner", refTarget); code != 0 {
		t.Fatalf("with flag: exit %d: %s", code, h.errb.String())
	}
	if r, _ := h.knownRecord(t); r.OwnerID != 99 {
		t.Errorf("not re-pinned: %+v", r)
	}
}

func TestPullWithoutOwnerIDWarnsOnce(t *testing.T) {
	h := pinHarness(t, "", false)
	h.reg.ownerID = 0
	if code := h.run("pull", refTarget); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if n := strings.Count(h.errb.String(), "owner pinning is unavailable"); n != 1 {
		t.Errorf("warned %d times: %s", n, h.errb.String())
	}
}

func TestInspectShowsPinStatusAndNeverWrites(t *testing.T) {
	h := pinHarness(t, "", false)
	known := filepath.Join(h.env.credDir, "known.json")

	if code := h.run("inspect", refTarget); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if !strings.Contains(h.errb.String(), "not pinned yet") {
		t.Errorf("no pin status:\n%s", h.errb.String())
	}
	if _, err := os.Stat(known); err == nil {
		t.Fatal("inspect wrote known.json")
	}

	h.runArgs("--yes", "--allow-unenforced-egress", refTarget)
	before, _ := os.ReadFile(known)
	if code := h.run("inspect", refTarget); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.errb.String(), "matches the owner you pinned") {
		t.Errorf("match not reported:\n%s", h.errb.String())
	}
	h.reg.ownerID = 99
	if code := h.run("inspect", refTarget); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if e := h.errb.String(); !strings.Contains(e, "taken over") || !strings.Contains(e, "99") || !strings.Contains(e, "7") {
		t.Errorf("mismatch not reported:\n%s", e)
	}
	if after, _ := os.ReadFile(known); string(after) != string(before) {
		t.Error("inspect modified known.json")
	}
}

func TestKnownListAndForget(t *testing.T) {
	h := pinHarness(t, "", false)
	if code := h.run("known"); code != 0 || !strings.Contains(h.out.String(), "no remembered") {
		t.Fatalf("empty: exit %d out %q", code, h.out.String())
	}
	h.runArgs("--yes", "--allow-unenforced-egress", refTarget)
	// A hostile name in the file must not reach the terminal raw.
	newKnownStore(h.env, &strings.Builder{}).update(h.env.registry, "evil", "n\x1b[31mx", func(r *knownRecord) { r.OwnerID = 5 })

	if code := h.run("known"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	out := h.out.String()
	if !strings.Contains(out, "alice/pr-reviewer") || !strings.Contains(out, "7") {
		t.Errorf("table:\n%s", out)
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("control character in table: %q", out)
	}

	if code := h.run("known", "forget", "alice/pr-reviewer"); code != 0 {
		t.Fatalf("forget exit %d: %s", code, h.errb.String())
	}
	if _, ok := h.knownRecord(t); ok {
		t.Error("record still present")
	}
	if code := h.run("known", "forget", "alice/pr-reviewer"); code != 1 {
		t.Errorf("forgetting an unknown bundle: exit %d", code)
	}
	if code := h.run("known", "forget"); code != 2 {
		t.Errorf("forget without arg: exit %d", code)
	}
}
