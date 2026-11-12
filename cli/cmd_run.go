package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/MasonD-007/capm/cli/internal/client"
	"github.com/MasonD-007/capm/cli/internal/sbx"
	"github.com/MasonD-007/capm/manifest"
)

const runUse = "usage: capm run [--yes] [--workdir DIR] [--model-url URL] [--model-key KEY] [--model NAME] [--allow-unenforced-egress] [--allow-global-anthropic-secret] <dir | user/name[@version]>"

// runDefaults fills in the interactive pieces of e that tests may inject.
func (e env) runDefaults(stdout, stderr io.Writer) env {
	if e.stdin == nil {
		e.stdin = os.Stdin
	}
	if e.isTTY == nil {
		e.isTTY = func() bool { return term.IsTerminal(int(os.Stdin.Fd())) }
	}
	if e.getenv == nil {
		e.getenv = os.Getenv
	}
	if e.readSecret == nil {
		e.readSecret = func(prompt string) (string, error) {
			fmt.Fprint(stderr, prompt)
			b, err := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(stderr)
			return string(b), err
		}
	}
	if e.runner == nil {
		e.runner = sbx.ExecRunner{Stdin: os.Stdin, Stdout: stdout, Stderr: stderr}
	}
	if e.ctx == nil {
		e.ctx = context.Background()
	}
	return e
}

type runFlags struct {
	yes, allowUnenforced        bool
	allowGlobalAnthropic        bool
	workdir, modelURL, modelKey string
	modelName                   string
	target                      string
}

// parseRunFlags accepts flags before and after the single positional target.
func parseRunFlags(args []string, stderr io.Writer) (runFlags, error) {
	var f runFlags
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.BoolVar(&f.yes, "yes", false, "")
	fs.BoolVar(&f.yes, "y", false, "")
	fs.BoolVar(&f.allowUnenforced, "allow-unenforced-egress", false, "")
	fs.BoolVar(&f.allowGlobalAnthropic, "allow-global-anthropic-secret", false, "")
	fs.StringVar(&f.workdir, "workdir", "", "")
	fs.StringVar(&f.modelURL, "model-url", "", "")
	fs.StringVar(&f.modelKey, "model-key", "", "")
	fs.StringVar(&f.modelName, "model", "", "")
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return f, err
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) != 1 {
		return f, errors.New("expected exactly one bundle")
	}
	f.target = pos[0]
	return f, nil
}

// runCmd implements `capm run`.
func runCmd(args []string, stdout, stderr io.Writer, e env) int {
	f, err := parseRunFlags(args, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "capm run: %v\n%s\n", err, runUse)
		return 2
	}
	e = e.runDefaults(stdout, stderr)
	ctx, stop := signal.NotifyContext(e.ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "capm run: "+format+"\n", a...)
		return 1
	}

	if f.workdir == "" {
		if f.workdir, err = os.Getwd(); err != nil {
			return fail("%v", err)
		}
	}
	modelURL := firstNonEmpty(f.modelURL, e.getenv("CAPM_MODEL_URL"))
	modelKey := firstNonEmpty(f.modelKey, e.getenv("CAPM_MODEL_KEY"))
	modelName := firstNonEmpty(f.modelName, e.getenv("CAPM_MODEL"))
	if modelURL == "" {
		return fail("no model endpoint: pass --model-url or set CAPM_MODEL_URL")
	}
	if f.modelKey != "" {
		fmt.Fprintln(stderr, "warning: --model-key is visible to other processes; prefer CAPM_MODEL_KEY")
	}

	// Locate the bundle: an existing path is local, otherwise a reference.
	var m *manifest.Manifest
	bundleDir := f.target
	if _, serr := os.Stat(f.target); serr != nil {
		owner, name, spec, perr := parseRef(f.target)
		if perr != nil {
			if strings.Contains(f.target, "@") {
				fmt.Fprintf(stderr, "capm run: %v\n%s\n", perr, runUse)
				return 2
			}
			return fail("%v", serr)
		}
		var res client.Resolved
		m, bundleDir, res, err = fetchToTemp(e, owner, name, spec, e.tempRoot, "capm-run-bundle-*")
		if bundleDir != "" {
			defer os.RemoveAll(bundleDir)
		}
		if err != nil {
			var re *client.RemovedError
			if errors.As(err, &re) {
				fmt.Fprintln(stderr, err)
				return 1
			}
			return fail("%v", err)
		}
		fmt.Fprintf(stderr, "running registry %s/%s@%s\n", owner, name, res.Version)
		warnYanked(stderr, owner, name, res)
	} else {
		fmt.Fprintf(stderr, "running local %s\n", client.Sanitize(f.target))
		if m, err = loadLocal(f.target); err != nil {
			return fail("%v", err)
		}
	}

	tmp, err := os.MkdirTemp(e.tempRoot, "capm-run-*")
	if err != nil {
		return fail("%v", err)
	}
	var plan sbx.Plan
	started := false
	defer func() {
		// Runs on success, failure and interrupt: undo sbx state, then
		// delete generated files, including any holding a secret.
		if started {
			cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
			for _, a := range plan.Cleanup {
				if err := e.runner.Run(cctx, sbx.Bin, a...); err != nil {
					fmt.Fprintf(stderr, "warning: cleanup `sbx %s` failed: %v\n", strings.Join(a, " "), err)
				}
			}
			cancel()
		}
		os.RemoveAll(tmp)
	}()
	// Resolve into a new variable: the deferred RemoveAll above must keep
	// the original path even when resolution fails.
	tmpReal, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		return fail("%v", err)
	}

	opts := sbx.Options{WorkDir: f.workdir, BundleDir: bundleDir, TempDir: tmpReal,
		SandboxName:  sandboxName(m.Metadata.Name),
		ModelBaseURL: modelURL, ModelKey: modelKey, ModelName: modelName,
		AllowGlobalAnthropicSecret: f.allowGlobalAnthropic}
	// Read-only: which global sbx secrets could leak into this sandbox (I3).
	if out, lerr := e.runner.Output(ctx, sbx.Bin, "secret", "ls", "--global", "--quiet"); lerr == nil {
		opts.GlobalSecrets, opts.GlobalSecretsChecked = sbx.ParseSecretList(out), true
	}
	info, err := sbx.Describe(m, opts)
	if err != nil {
		return fail("%v", err)
	}
	fmt.Fprint(stdout, m.EnforcedSummary().Render())
	fmt.Fprint(stdout, renderRunInfo(m, info))

	if !info.Enforced && !f.allowUnenforced {
		return fail("refusing to start: egress to exactly the listed hosts cannot be enforced; pass --allow-unenforced-egress to run anyway")
	}
	if !f.yes {
		if !e.isTTY() {
			return fail("stdin is not a terminal; pass --yes to run without confirmation")
		}
		fmt.Fprint(stdout, "\nProceed? [y/N] ")
		line, _ := bufio.NewReader(e.stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			return fail("aborted; nothing was run")
		}
	}
	if ctx.Err() != nil {
		return fail("interrupted; nothing was run")
	}

	opts.Secrets = map[string]string{}
	for _, s := range m.Secrets {
		v := e.getenv("CAPM_SECRET_" + s.Name)
		if v == "" && e.isTTY() {
			if v, err = e.readSecret(fmt.Sprintf("Value for secret %s (input hidden): ", s.Name)); err != nil {
				return fail("reading secret %s: %v", s.Name, err)
			}
		}
		if v == "" {
			return fail("no value for secret %s: set CAPM_SECRET_%s or run interactively", s.Name, s.Name)
		}
		opts.Secrets[s.Name] = v
	}
	if ctx.Err() != nil {
		return fail("interrupted; nothing was run")
	}
	if plan, err = sbx.BuildPlan(m, opts); err != nil {
		return fail("%v", err)
	}
	for _, fl := range plan.Files {
		if err := os.MkdirAll(filepath.Dir(fl.Path), 0o700); err != nil {
			return fail("%v", err)
		}
		if err := os.WriteFile(fl.Path, fl.Content, fl.Mode); err != nil {
			return fail("%v", err)
		}
	}

	for i, a := range plan.Args {
		if ctx.Err() != nil {
			break
		}
		started = true
		c := ctx
		if i == plan.Attach {
			// The agent owns the terminal: Ctrl-C belongs to it, not to us.
			c = context.WithoutCancel(ctx)
		}
		if check, ok := plan.Verify[i]; ok {
			var out []byte
			if out, err = e.runner.Output(c, sbx.Bin, a...); err == nil {
				if err = check(out); err != nil {
					if ctx.Err() != nil {
						break
					}
					return fail("%s", client.Sanitize(err.Error()))
				}
			}
		} else if in, ok := plan.Stdin[i]; ok {
			err = e.runner.RunWithStdin(c, strings.NewReader(in), sbx.Bin, a...)
		} else {
			err = e.runner.Run(c, sbx.Bin, a...)
		}
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			return fail("`sbx %s` failed: %v", strings.Join(a[:min(2, len(a))], " "), err)
		}
	}
	if ctx.Err() != nil {
		return fail("interrupted; cleaning up")
	}
	return 0
}

func renderRunInfo(m *manifest.Manifest, info sbx.Info) string {
	var b strings.Builder
	d := manifest.DisplaySafe
	b.WriteString("\nRun plan (Docker Sandboxes; not yet verified against a real sandbox)\n")
	fmt.Fprintf(&b, "  Base agent kit: %s\n", d(info.KitRef))
	if len(info.BaseAgentHosts) > 0 {
		fmt.Fprintf(&b, "  Base agent (sbx) egress: %s (%s)\n", strings.Join(info.BaseAgentHosts, ", "), info.BaseAgentNote)
	} else {
		fmt.Fprintf(&b, "  Base agent (sbx) egress: %s\n", info.BaseAgentNote)
	}
	fmt.Fprintf(&b, "  Model endpoint (supplied by you): %s:443, allowed for this sandbox only\n", client.Sanitize(info.ModelHost))
	for _, r := range info.SecretRoutes {
		hosts := make([]string, len(r.Hosts))
		for i, h := range r.Hosts {
			hosts[i] = d(h)
		}
		fmt.Fprintf(&b, "  Secret %s goes only to: %s (%s)\n", d(r.Name), strings.Join(hosts, ", "), r.Via)
	}
	for _, mt := range info.Mounts {
		mode := "read-write"
		if mt.ReadOnly {
			mode = "read-only"
		}
		fmt.Fprintf(&b, "  Mount: %s -> %s (%s)\n", d(mt.Path), client.Sanitize(mt.HostPath), mode)
	}
	if info.ContextDest != "" {
		fmt.Fprintf(&b, "  Context files delivered to: %s (content not verified)\n", info.ContextDest)
	}
	if len(m.MCP) > 0 {
		b.WriteString("  MCP servers are registered with the sbx MCP gateway on this machine for this run, checked to be remote endpoints at the declared URL, and removed afterwards\n")
	}
	b.WriteString("  Host skills store: not linked into the sandbox (--skills off)\n")
	fmt.Fprintf(&b, "  Egress enforcement: %s\n", info.EnforcementMsg)
	if len(info.Warnings) > 0 {
		b.WriteString("Warnings:\n")
		for _, w := range info.Warnings {
			fmt.Fprintf(&b, "  - %s\n", d(w))
		}
	}
	return b.String()
}

func loadLocal(dir string) (*manifest.Manifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, manifest.FileName))
	if err != nil {
		return nil, err
	}
	m, err := manifest.Parse(data)
	if err == nil {
		err = m.Validate()
	}
	if err != nil {
		return nil, fmt.Errorf("invalid manifest:\n%v", err)
	}
	return m, nil
}

func sandboxName(bundle string) string {
	b := make([]byte, 3)
	rand.Read(b)
	if len(bundle) > 40 {
		bundle = strings.TrimRight(bundle[:40], "-")
	}
	return "capm-" + bundle + "-" + hex.EncodeToString(b)
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
