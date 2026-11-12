package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/MasonD-007/capm/cli/internal/client"
	"github.com/MasonD-007/capm/manifest"
)

const sampleLabels = "[caution] context_files: Reads context files (1): prompts/review.md"

func TestInspectLocalPrintsRiskLabelsAfterSummary(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"inspect", "testdata/pr-reviewer"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	s := out.String()
	sum, risk := strings.Index(s, "Model endpoint: supplied by you"), strings.Index(s, manifest.RiskLabelsHeading)
	if sum < 0 || risk < sum {
		t.Fatalf("risk section must follow the summary:\n%s", s)
	}
	for _, want := range []string{sampleLabels, "[caution] mcp_servers: Uses MCP servers (1): gh (mcp.example.com)",
		"[caution] secrets_declared: Declares secrets (1): GITHUB_TOKEN", "[info] mounts_read_only: Mounts are all read-only (1): ./workspace"} {
		if !strings.Contains(s[risk:], want) {
			t.Errorf("missing %q:\n%s", want, s[risk:])
		}
	}
	// The existing summary is untouched: it is a strict prefix.
	if !strings.HasPrefix(s, mustRender(t)) {
		t.Errorf("summary output changed")
	}
}

func mustRender(t *testing.T) string {
	t.Helper()
	m, err := manifest.Parse(readFile(t, "testdata/pr-reviewer/capm.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return m.EnforcedSummary().Render()
}

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInspectRemoteRecomputesRiskLabels(t *testing.T) {
	h := newHarness(t)
	h.reg.add("bob", "agent", "1.0.0", testBundleTar(t, "agent", "1.0.0"), false)
	h.reg.metaRiskLabels = []map[string]string{{"id": "fake_label", "severity": "high", "reason": "server says so"}}
	if code := h.run("inspect", "bob/agent"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	s := h.out.String()
	if strings.Contains(s, "fake_label") || strings.Contains(s, "server says so") {
		t.Errorf("server labels must be ignored:\n%s", s)
	}
	if !strings.Contains(s, manifest.RiskLabelsHeading) {
		t.Errorf("no risk section:\n%s", s)
	}
}

func TestInspectShowsNeutralLineWhenNoLabels(t *testing.T) {
	h := newHarness(t)
	h.reg.add("bob", "agent", "1.0.0", testBundleTar(t, "agent", "1.0.0"), false)
	if code := h.run("inspect", "bob/agent"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if s := h.out.String(); !strings.Contains(s, "("+manifest.NoRiskLabelsText+")") {
		t.Errorf("neutral line missing:\n%s", s)
	}
}

func TestRunPrintsRiskLabelsBeforePrompt(t *testing.T) {
	h := newRunHarness(t, "n\n", true)
	if code := h.runArgs("--allow-unenforced-egress", fixtureDir); code != 1 {
		t.Fatalf("exit %d; stderr %s", code, h.errb.String())
	}
	s := h.out.String()
	risk, prompt := strings.Index(s, manifest.RiskLabelsHeading), strings.Index(s, "Proceed?")
	if risk < 0 || prompt < 0 || risk > prompt || !strings.Contains(s, sampleLabels) {
		t.Errorf("risk labels must be shown before the prompt:\n%s", s)
	}
}

func TestListMarkerFromServerRisk(t *testing.T) {
	ls := newListServer(t, fixed(
		client.BundleInfo{Owner: "a", Name: "hi", Latest: "1.0.0", Risk: "high", Description: "d1"},
		client.BundleInfo{Owner: "a", Name: "ca", Latest: "1.0.0", Risk: "caution", Description: "d2"},
		client.BundleInfo{Owner: "a", Name: "in", Latest: "1.0.0", Risk: "info", Description: "d3"},
		client.BundleInfo{Owner: "a", Name: "no", Latest: "1.0.0", Description: "d4"},
		client.BundleInfo{Owner: "a", Name: "ev", Latest: "1.0.0", Risk: "\x1b[31mhigh", Description: "d5"},
	))
	code, out, errs := ls.run("list")
	if code != 0 || errs != "" {
		t.Fatalf("code %d %q", code, errs)
	}
	want := map[string]string{"a/hi": "!!", "a/ca": "!", "a/in": "", "a/no": "", "a/ev": ""}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		f := strings.Fields(line)
		name := f[0]
		got := ""
		if len(f) == 4 {
			got = f[2]
		}
		if got != want[name] {
			t.Errorf("%s marker = %q, want %q (line %q)", name, got, want[name], line)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("escape reached terminal: %q", out)
	}
}

// With no marker to show (older server, or nothing flagged) the table is
// exactly what it was before risk markers existed.
func TestListWithoutMarkersIsUnchanged(t *testing.T) {
	ls := newListServer(t, fixed(client.BundleInfo{Owner: "alice", Name: "x", Latest: "1.0.0", Risk: "info", Description: "Reviews"}))
	_, out, _ := ls.run("list")
	if want := "alice/x  1.0.0  Reviews\n"; out != want {
		t.Errorf("out %q, want %q", out, want)
	}
}

func TestListUsageStatesMarkerIsRegistryClaim(t *testing.T) {
	var out, errb bytes.Buffer
	run([]string{"help"}, &out, &errb)
	s := out.String() + errb.String()
	for _, w := range []string{"registry's claim", "capm inspect"} {
		if !strings.Contains(s, w) {
			t.Errorf("usage lacks %q:\n%s", w, s)
		}
	}
}
