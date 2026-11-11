package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/MasonD-007/capm/manifest"
)

const (
	runSecret   = "SENTINEL-run-secret-77aa"
	runModelKey = "SENTINEL-run-model-88bb"
)

type call struct {
	args  []string
	stdin string
}

// fakeRunner records sbx invocations instead of running them.
type fakeRunner struct {
	mu     sync.Mutex
	calls  []call
	failOn string              // first arg that makes Run fail
	onCall func(args []string) // hook, e.g. to cancel the context
	seen   []string            // temp files that existed during the run

	// Output: read-only queries are recorded apart from calls, so "nothing
	// was run" checks still count only state-changing invocations.
	queries    [][]string
	secretList string // stdout of `secret ls`
	secretErr  error
	inspectOut string // stdout of `mcp inspect`; "" means a good remote
}

func (f *fakeRunner) record(name, stdin string, args []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if name != "sbx" {
		return errors.New("unexpected binary " + name)
	}
	f.calls = append(f.calls, call{args, stdin})
	for i, a := range args {
		if a == "--command" && i+1 < len(args) {
			f.seen = append(f.seen, strings.TrimPrefix(args[i+1], "cat "))
		}
	}
	if f.onCall != nil {
		f.onCall(args)
	}
	if f.failOn != "" && args[0] == f.failOn {
		return errors.New("sbx failed")
	}
	return nil
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return f.record(name, "", args)
}

func (f *fakeRunner) RunWithStdin(ctx context.Context, stdin io.Reader, name string, args ...string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b, _ := io.ReadAll(stdin)
	return f.record(name, string(b), args)
}

func (f *fakeRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.queries = append(f.queries, args)
	f.mu.Unlock()
	switch {
	case len(args) >= 2 && args[0] == "secret" && args[1] == "ls":
		return []byte(f.secretList), f.secretErr
	case len(args) >= 2 && args[0] == "mcp" && args[1] == "inspect":
		if f.inspectOut != "" {
			return []byte(f.inspectOut), nil
		}
		// The fixture's MCP server, as a remote endpoint.
		if err := f.record(name, "", args); err != nil {
			return nil, err
		}
		return []byte(`{"name":"` + args[2] + `","type":"remote","url":"https://mcp.example.com/mcp"}`), nil
	}
	return nil, errors.New("unexpected query")
}

func (f *fakeRunner) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

func (f *fakeRunner) has(first ...string) bool {
	for _, c := range f.calls {
		if len(c.args) >= len(first) && strings.Join(c.args[:len(first)], " ") == strings.Join(first, " ") {
			return true
		}
	}
	return false
}

type runHarness struct {
	*harness
	runner  *fakeRunner
	tmpRoot string
	work    string
	vars    map[string]string
	prompts []string
}

func newRunHarness(t *testing.T, stdin string, tty bool) *runHarness {
	h := &runHarness{harness: newHarness(t), runner: &fakeRunner{}, tmpRoot: t.TempDir(), work: t.TempDir()}
	os.Mkdir(filepath.Join(h.work, "workspace"), 0o755)
	h.vars = map[string]string{
		"CAPM_MODEL_URL":           "https://models.example.com",
		"CAPM_MODEL_KEY":           runModelKey,
		"CAPM_SECRET_GITHUB_TOKEN": runSecret,
	}
	h.env.stdin = strings.NewReader(stdin)
	h.env.isTTY = func() bool { return tty }
	h.env.getenv = func(k string) string { return h.vars[k] }
	h.env.runner = h.runner
	h.env.tempRoot = h.tmpRoot
	h.env.readSecret = func(prompt string) (string, error) {
		h.prompts = append(h.prompts, prompt)
		return "prompted-value", nil
	}
	return h
}

func (h *runHarness) runArgs(extra ...string) int {
	args := append([]string{"run", "--workdir", h.work}, extra...)
	return h.run(args...)
}

func (h *runHarness) assertNoLeaks(t *testing.T) {
	t.Helper()
	all := h.out.String() + h.errb.String()
	for _, v := range []string{runSecret, runModelKey, "prompted-value"} {
		if strings.Contains(all, v) {
			t.Errorf("secret value printed:\n%s", all)
		}
	}
	for _, c := range h.runner.calls {
		for _, a := range c.args {
			if strings.Contains(a, runSecret) || strings.Contains(a, runModelKey) {
				t.Errorf("secret value in sbx args: %v", c.args)
			}
		}
	}
	ents, _ := os.ReadDir(h.tmpRoot)
	if len(ents) != 0 {
		t.Errorf("temp files left behind: %v", ents)
	}
	for _, p := range h.runner.seen {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("secret file %s still exists", p)
		}
	}
}

const fixtureDir = "testdata/pr-reviewer"

func TestRunRefusesUnenforcedEgress(t *testing.T) {
	h := newRunHarness(t, "y\n", true)
	if code := h.runArgs("--yes", fixtureDir); code != 1 {
		t.Fatalf("exit %d, want 1; stderr %s", code, h.errb.String())
	}
	if h.runner.count() != 0 {
		t.Errorf("runner called %d times", h.runner.count())
	}
	s := h.out.String()
	if !strings.Contains(s, "NOT ENFORCED") || !strings.Contains(h.errb.String(), "--allow-unenforced-egress") {
		t.Errorf("stdout %q stderr %q", s, h.errb.String())
	}
	h.assertNoLeaks(t)
}

func TestRunDeclineRunsNothing(t *testing.T) {
	h := newRunHarness(t, "n\n", true)
	if code := h.runArgs("--allow-unenforced-egress", fixtureDir); code != 1 {
		t.Fatalf("exit %d; stderr %s", code, h.errb.String())
	}
	if h.runner.count() != 0 {
		t.Errorf("runner called %d times", h.runner.count())
	}
	s := h.out.String()
	for _, want := range []string{"Network (declared bundle egress", "api.github.com", "Base agent (sbx) egress", "api.anthropic.com",
		"Model endpoint (supplied by you): models.example.com", "Egress enforcement: NOT ENFORCED", "/home/agent/.claude/CLAUDE.md", "not verified", "Proceed?"} {
		if !strings.Contains(s, want) {
			t.Errorf("confirmation lacks %q:\n%s", want, s)
		}
	}
	h.assertNoLeaks(t)
}

func TestRunNonInteractiveWithoutYesRefuses(t *testing.T) {
	h := newRunHarness(t, "y\n", false)
	if code := h.runArgs("--allow-unenforced-egress", fixtureDir); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if h.runner.count() != 0 || !strings.Contains(h.errb.String(), "--yes") {
		t.Errorf("calls %d stderr %q", h.runner.count(), h.errb.String())
	}
}

func TestRunYesExecutesPlanAndCleansUp(t *testing.T) {
	h := newRunHarness(t, "", false)
	if code := h.runArgs("--yes", "--allow-unenforced-egress", fixtureDir); code != 0 {
		t.Fatalf("exit %d; stderr %s", code, h.errb.String())
	}
	if strings.Contains(h.out.String(), "Proceed?") {
		t.Error("--yes still prompted")
	}
	for _, want := range [][]string{{"kit", "pack"}, {"mcp", "add"}, {"create"}, {"run", "--name"}, {"rm", "--force"}, {"mcp", "rm"}} {
		if !h.runner.has(want...) {
			t.Errorf("no %v call: %v", want, h.runner.calls)
		}
	}
	var mcpStdin string
	for _, c := range h.runner.calls {
		if c.args[0] == "secret" && c.args[1] == "set" {
			mcpStdin = c.stdin
		}
	}
	if mcpStdin != runSecret {
		t.Errorf("MCP secret stdin %q", mcpStdin)
	}
	if len(h.runner.seen) == 0 {
		t.Error("no secret file was referenced")
	}
	h.assertNoLeaks(t)
}

func TestRunFailureStillCleansUp(t *testing.T) {
	h := newRunHarness(t, "", false)
	h.runner.failOn = "create"
	if code := h.runArgs("--yes", "--allow-unenforced-egress", fixtureDir); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if h.runner.has("run", "--name") {
		t.Error("attached after a failed create")
	}
	if !h.runner.has("rm", "--force") || !h.runner.has("mcp", "rm") {
		t.Errorf("cleanup not run: %v", h.runner.calls)
	}
	h.assertNoLeaks(t)
}

func TestRunCancelCleansUp(t *testing.T) {
	h := newRunHarness(t, "", false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	h.env.ctx = ctx
	h.runner.onCall = func(args []string) {
		if args[0] == "mcp" && args[1] == "add" {
			cancel() // Ctrl-C
		}
	}
	if code := h.runArgs("--yes", "--allow-unenforced-egress", fixtureDir); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if h.runner.has("create") {
		t.Error("kept going after cancel")
	}
	if !h.runner.has("mcp", "rm") {
		t.Errorf("cleanup not run after cancel: %v", h.runner.calls)
	}
	h.assertNoLeaks(t)
}

func TestRunMissingSecretNamesIt(t *testing.T) {
	h := newRunHarness(t, "", false)
	delete(h.vars, "CAPM_SECRET_GITHUB_TOKEN")
	if code := h.runArgs("--yes", "--allow-unenforced-egress", fixtureDir); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.errb.String(), "GITHUB_TOKEN") || h.runner.count() != 0 {
		t.Errorf("stderr %q calls %d", h.errb.String(), h.runner.count())
	}
	h.assertNoLeaks(t)
}

func TestRunPromptsForSecretOnTTY(t *testing.T) {
	h := newRunHarness(t, "y\n", true)
	delete(h.vars, "CAPM_SECRET_GITHUB_TOKEN")
	if code := h.runArgs("--allow-unenforced-egress", fixtureDir); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if len(h.prompts) != 1 || !strings.Contains(h.prompts[0], "GITHUB_TOKEN") {
		t.Errorf("prompts %v", h.prompts)
	}
	h.assertNoLeaks(t)
}

func TestRunMountEscapeRefused(t *testing.T) {
	h := newRunHarness(t, "", false)
	os.Remove(filepath.Join(h.work, "workspace"))
	os.Symlink(t.TempDir(), filepath.Join(h.work, "workspace"))
	if code := h.runArgs("--yes", "--allow-unenforced-egress", fixtureDir); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if h.runner.count() != 0 || !strings.Contains(h.errb.String(), "workspace") {
		t.Errorf("stderr %q", h.errb.String())
	}
}

func TestRunUsage(t *testing.T) {
	h := newRunHarness(t, "", false)
	if code := h.run("run"); code != 2 {
		t.Errorf("no args: exit %d", code)
	}
	if code := h.run("run", "--bogus", fixtureDir); code != 2 {
		t.Errorf("bad flag: exit %d", code)
	}
	if code := h.run("run", "a", "b"); code != 2 {
		t.Errorf("two targets: exit %d", code)
	}
	delete(h.vars, "CAPM_MODEL_URL")
	if code := h.runArgs("--yes", fixtureDir); code != 1 || !strings.Contains(h.errb.String(), "--model-url") {
		t.Errorf("no model url: exit %d stderr %q", code, h.errb.String())
	}
}

func TestRunFlagsAfterTarget(t *testing.T) {
	h := newRunHarness(t, "", false)
	if code := h.run("run", fixtureDir, "--workdir", h.work, "--yes", "--allow-unenforced-egress"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
}

func TestRunRemoteRef(t *testing.T) {
	h := newRunHarness(t, "", false)
	tarball, err := manifest.PackDir(fixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	h.reg.add("alice", "pr-reviewer", "0.1.0", tarball, false)
	chdirTemp(t) // a pull must not write into the working directory
	if code := h.runArgs("--yes", "--allow-unenforced-egress", "alice/pr-reviewer@0.1.0"); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if !h.runner.has("create") {
		t.Error("plan not executed")
	}
	if ents, _ := os.ReadDir("."); len(ents) != 0 {
		t.Errorf("run wrote into cwd: %v", ents)
	}
	h.assertNoLeaks(t)
}

func TestRunUsageListed(t *testing.T) {
	var out, errb bytes.Buffer
	run([]string{"help"}, &out, &errb)
	if !strings.Contains(out.String(), "--allow-unenforced-egress") {
		t.Errorf("usage lacks run flags:\n%s", out.String())
	}
}

// C2: a registration that sbx reports as non-remote, or at another URL,
// aborts the run before create and still cleans up.
func TestRunAbortsOnNonRemoteMCP(t *testing.T) {
	for name, out := range map[string]string{
		"stdio":     `{"type":"stdio","image":"docker.io/evil/mcp:1"}`,
		"other url": `{"type":"remote","url":"https://evil.example.com/mcp"}`,
		"garbage":   "\x1b[2Jnot json",
	} {
		t.Run(name, func(t *testing.T) {
			h := newRunHarness(t, "", false)
			h.runner.inspectOut = out
			if code := h.runArgs("--yes", "--allow-unenforced-egress", fixtureDir); code != 1 {
				t.Fatalf("exit %d; stderr %s", code, h.errb.String())
			}
			if h.runner.has("create") || h.runner.has("run", "--name") {
				t.Errorf("kept going after a failed MCP check: %v", h.runner.calls)
			}
			if !h.runner.has("mcp", "rm") || !h.runner.has("secret", "rm") {
				t.Errorf("cleanup not run: %v", h.runner.calls)
			}
			if !strings.Contains(h.errb.String(), "MCP server gh") || strings.Contains(h.errb.String(), "\x1b") {
				t.Errorf("stderr %q", h.errb.String())
			}
			h.assertNoLeaks(t)
		})
	}
}

// C2: every mcp add the CLI executes carries a header.
func TestRunEveryMCPAddHasHeader(t *testing.T) {
	h := newRunHarness(t, "", false)
	if code := h.runArgs("--yes", "--allow-unenforced-egress", fixtureDir); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	n := 0
	for _, c := range h.runner.calls {
		if len(c.args) > 1 && c.args[0] == "mcp" && c.args[1] == "add" {
			n++
			if !strings.Contains(strings.Join(c.args, " "), "--header X-Capm-Bundle: capm-pr-reviewer-") {
				t.Errorf("mcp add without header: %v", c.args)
			}
		}
	}
	if n != 1 || !h.runner.has("mcp", "inspect") {
		t.Errorf("adds %d, calls %v", n, h.runner.calls)
	}
}

// I3: a global anthropic sbx secret blocks the run unless explicitly allowed.
func TestRunGlobalAnthropicSecret(t *testing.T) {
	h := newRunHarness(t, "", false)
	h.runner.secretList = "anthropic\ngithub\n"
	if code := h.runArgs("--yes", "--allow-unenforced-egress", fixtureDir); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if h.runner.count() != 0 || !strings.Contains(h.errb.String(), "--allow-global-anthropic-secret") {
		t.Errorf("calls %d stderr %q", h.runner.count(), h.errb.String())
	}
	h.assertNoLeaks(t)

	h = newRunHarness(t, "", false)
	h.runner.secretList = "anthropic\n"
	if code := h.runArgs("--yes", "--allow-unenforced-egress", "--allow-global-anthropic-secret", fixtureDir); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if !strings.Contains(h.out.String(), "global sbx secrets stored on this machine: anthropic") {
		t.Errorf("no warning line:\n%s", h.out.String())
	}

	h = newRunHarness(t, "", false)
	h.runner.secretErr = errors.New("not signed in")
	if code := h.runArgs("--yes", "--allow-unenforced-egress", fixtureDir); code != 1 || !strings.Contains(h.errb.String(), "could not list global sbx secrets") {
		t.Errorf("unlistable secrets: exit %d stderr %q", code, h.errb.String())
	}
}

// I4 + I3: the run screen lists per-secret destinations and the skills mode.
func TestRunScreenSecretDestinations(t *testing.T) {
	h := newRunHarness(t, "n\n", true)
	h.runArgs("--allow-unenforced-egress", fixtureDir)
	s := h.out.String()
	for _, want := range []string{
		"Secret GITHUB_TOKEN goes only to: mcp.example.com (host MCP gateway only)",
		"Secret model key goes only to: models.example.com",
		"--skills off",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("run screen lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "injected by the sbx proxy only on requests to: api.github.com") {
		t.Errorf("old all-secrets line still printed:\n%s", s)
	}
}
