package sbx

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/MasonD-007/capm/manifest"
)

const (
	sentinelSecret = "SENTINEL-bundle-secret-9f8e7d"
	sentinelMCP    = "SENTINEL-mcp-token-1a2b3c"
	sentinelModel  = "SENTINEL-model-key-4d5e6f"
	modelURL       = "https://models.example.com/v1"
	contextText    = "Review every pull request carefully."
)

type fixture struct {
	m       *manifest.Manifest
	opts    Options
	workdir string // symlink-resolved
}

func newFixture(t *testing.T, agent, version string) fixture {
	t.Helper()
	bundle := t.TempDir()
	if err := os.MkdirAll(filepath.Join(bundle, "prompts"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(bundle, "prompts", "review.md"), []byte(contextText), 0o644)
	work := t.TempDir()
	os.Mkdir(filepath.Join(work, "workspace"), 0o755)
	os.Mkdir(filepath.Join(work, "out"), 0o755)
	tmp := t.TempDir()
	m := &manifest.Manifest{
		APIVersion: "capm/v0", Kind: "Agent",
		Metadata:  manifest.Metadata{Name: "pr-reviewer", Version: "0.1.0"},
		Base:      manifest.Base{Agent: agent, Version: version},
		Interface: manifest.Interface{Type: "tty"},
		Model:     manifest.Model{API: "openai-compatible", Requires: manifest.ModelRequires{ToolCalling: true, MinContextTokens: 32000}},
		Permissions: manifest.Permissions{
			// Unsorted with a duplicate: the plan must use the summary's form.
			Egress: []string{"api.github.com", "api.example.org", "api.github.com"},
			Mounts: []manifest.Mount{{Path: "./workspace", Mode: "read-only"}, {Path: "out", Mode: "read-write"}},
		},
		Secrets: []manifest.Secret{{Name: "GITHUB_TOKEN"}, {Name: "API_TOKEN"}},
		MCP:     []manifest.MCP{{Name: "gh", URL: "https://mcp.example.com/mcp", Secret: "GITHUB_TOKEN"}},
		Context: []string{"prompts/review.md"},
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("fixture manifest invalid: %v", err)
	}
	rw, _ := filepath.EvalSymlinks(work)
	return fixture{m: m, workdir: rw, opts: Options{
		WorkDir: work, BundleDir: bundle, TempDir: tmp, SandboxName: "capm-pr-reviewer-abc123",
		ModelBaseURL: modelURL, ModelKey: sentinelModel, ModelName: "qwen3-coder", GlobalSecretsChecked: true,
		Secrets: map[string]string{"GITHUB_TOKEN": sentinelMCP, "API_TOKEN": sentinelSecret},
	}}
}

// step returns the first invocation whose leading words equal prefix.
func step(p Plan, prefix ...string) (int, []string) {
	for i, a := range p.Args {
		if len(a) >= len(prefix) && slices.Equal(a[:len(prefix)], prefix) {
			return i, a
		}
	}
	return -1, nil
}

func steps(p Plan, prefix ...string) [][]string {
	var out [][]string
	for _, a := range p.Args {
		if len(a) >= len(prefix) && slices.Equal(a[:len(prefix)], prefix) {
			out = append(out, a)
		}
	}
	return out
}

func flagValues(args []string, flag string) []string {
	var v []string
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			v = append(v, args[i+1])
		}
	}
	return v
}

func file(t *testing.T, p Plan, path string) File {
	t.Helper()
	for _, f := range p.Files {
		if f.Path == path {
			return f
		}
	}
	t.Fatalf("plan has no file %s; files: %v", path, fileNames(p))
	return File{}
}

func fileNames(p Plan) []string {
	var n []string
	for _, f := range p.Files {
		n = append(n, f.Path)
	}
	return n
}

type parsedMixin struct {
	SchemaVersion string `yaml:"schemaVersion"`
	Kind          string `yaml:"kind"`
	DisplayName   string `yaml:"displayName"`
	Description   string `yaml:"description"`
	Capabilities  []struct {
		Type   string         `yaml:"type"`
		Config map[string]any `yaml:"config"`
	} `yaml:"capabilities"`
}

func TestBuildPlanPerAgent(t *testing.T) {
	cases := []struct {
		agent, version, kit string
		ctxDir, ctxFile     string
		keyEnv              string
	}{
		{"claude-code", "2.1.292", "docker.io/docker/sbx-kit-claude:2.1.292", "/home/agent/.claude", "CLAUDE.md", "ANTHROPIC_API_KEY"},
		{"opencode", "1.18.33", "docker.io/docker/sbx-kit-opencode:1.18.33", "/home/agent/.config/opencode", "AGENTS.md", "CAPM_MODEL_KEY"},
	}
	for _, tc := range cases {
		t.Run(tc.agent, func(t *testing.T) {
			fx := newFixture(t, tc.agent, tc.version)
			p, err := BuildPlan(fx.m, fx.opts)
			if err != nil {
				t.Fatal(err)
			}
			sum := fx.m.EnforcedSummary()
			N := fx.opts.SandboxName

			// Egress: the mixin's runtime allow list is exactly the summary's egress.
			if !slices.Equal(p.Egress, sum.Egress) {
				t.Errorf("Egress %v, want %v", p.Egress, sum.Egress)
			}
			spec := file(t, p, filepath.Join(fx.opts.TempDir, "mixin", "spec.yaml"))
			var ms parsedMixin
			dec := yaml.NewDecoder(strings.NewReader(string(spec.Content)))
			dec.KnownFields(true)
			if err := dec.Decode(&ms); err != nil {
				t.Fatalf("spec.yaml: %v\n%s", err, spec.Content)
			}
			if ms.SchemaVersion != "3" || ms.Kind != "mixin" {
				t.Errorf("spec header %+v", ms)
			}
			var allow []string
			var ctxCfg map[string]any
			for _, c := range ms.Capabilities {
				switch c.Type {
				case "com.docker.sandbox/network-policy@2":
					rt := c.Config["runtime"].(map[string]any)
					for _, h := range rt["allow"].([]any) {
						allow = append(allow, h.(string))
					}
				case "com.docker.sandbox/agent-context@2":
					ctxCfg = c.Config
				default:
					t.Errorf("unexpected capability %s", c.Type)
				}
			}
			var want []string
			for _, h := range sum.Egress {
				want = append(want, h+":443")
			}
			if !slices.Equal(allow, want) {
				t.Errorf("mixin allow %v, want %v", allow, want)
			}
			// The only per-sandbox network rule is the installer's model host.
			pol := steps(p, "policy", "allow", "network")
			if len(pol) != 1 || !slices.Equal(pol[0], []string{"policy", "allow", "network", "--sandbox", N, "models.example.com:443"}) {
				t.Errorf("policy steps %v", pol)
			}
			// MCP: registered through the gateway, never as egress.
			_, add := step(p, "mcp", "add")
			srv := N + "-gh"
			wantAdd := []string{"mcp", "add", srv, "--url", "https://mcp.example.com/mcp", "--skip-auth", "--header", "X-Capm-Bundle: " + N, "--header", "Authorization: Bearer ${github-token}"}
			if !slices.Equal(add, wantAdd) {
				t.Errorf("mcp add %v, want %v", add, wantAdd)
			}
			i, set := step(p, "secret", "set", "mcp:"+srv+":github-token")
			if set == nil || p.Stdin[i] != sentinelMCP {
				t.Errorf("mcp secret step %v stdin %q", set, p.Stdin[i])
			}
			for _, a := range p.Args {
				if a[0] == "mcp" && a[1] == "add" {
					continue
				}
				if strings.Contains(strings.Join(a, " "), "mcp.example.com") {
					t.Errorf("MCP host outside mcp add: %v", a)
				}
			}
			if strings.Contains(string(spec.Content), "mcp.example.com") {
				t.Errorf("MCP host in mixin egress:\n%s", spec.Content)
			}

			// create: pinned kit, capm workspace first, mounts with modes, mixin, MCP set, name.
			ci, create := step(p, "create")
			if create == nil {
				t.Fatalf("no create step: %v", p.Args)
			}
			ws := filepath.Join(fx.opts.TempDir, "workspace")
			wantPos := []string{"create", tc.kit, ws,
				filepath.Join(fx.workdir, "workspace") + ":ro",
				filepath.Join(fx.workdir, "out")}
			if !slices.Equal(create[:len(wantPos)], wantPos) {
				t.Errorf("create positionals %v, want %v", create[:len(wantPos)], wantPos)
			}
			if v := flagValues(create, "--kit"); !slices.Equal(v, []string{filepath.Join(fx.opts.TempDir, "mixin.zip")}) {
				t.Errorf("--kit %v", v)
			}
			if v := flagValues(create, "--static-mcp"); !slices.Equal(v, []string{srv}) {
				t.Errorf("--static-mcp %v", v)
			}
			if v := flagValues(create, "--name"); !slices.Equal(v, []string{N}) {
				t.Errorf("--name %v", v)
			}
			for _, mt := range p.Mounts {
				if rel, err := filepath.Rel(fx.workdir, mt.HostPath); err != nil || strings.HasPrefix(rel, "..") {
					t.Errorf("mount %s outside workdir", mt.HostPath)
				}
			}
			pi, _ := step(p, "kit", "pack")
			if pi < 0 || pi > ci {
				t.Errorf("kit pack must precede create: %v", p.Args)
			}
			if last := p.Args[len(p.Args)-1]; !slices.Equal(last, []string{"run", "--name", N}) || p.Attach != len(p.Args)-1 {
				t.Errorf("last step %v attach %d", last, p.Attach)
			}

			// Context: the documented destination per agent.
			if ctxCfg == nil || ctxCfg["directory"] != tc.ctxDir || ctxCfg["filename"] != tc.ctxFile ||
				!strings.Contains(ctxCfg["content"].(string), contextText) {
				t.Errorf("agent-context %v", ctxCfg)
			}
			if p.ContextDest != tc.ctxDir+"/"+tc.ctxFile {
				t.Errorf("ContextDest %q", p.ContextDest)
			}

			// Model endpoint, agent-specific.
			envs := flagValues(create, "-e")
			_, custom := step(p, "secret", "set-custom", "--sandbox", N, "--host", "models.example.com", "--env", tc.keyEnv)
			if custom == nil {
				t.Errorf("no model key binding for %s: %v", tc.keyEnv, p.Args)
			}
			switch tc.agent {
			case "claude-code":
				if !slices.Contains(envs, "ANTHROPIC_BASE_URL="+modelURL) {
					t.Errorf("-e %v lacks ANTHROPIC_BASE_URL", envs)
				}
			case "opencode":
				if len(envs) != 0 {
					t.Errorf("opencode should not get -e %v", envs)
				}
				oc := file(t, p, filepath.Join(ws, "opencode.json"))
				s := string(oc.Content)
				if !strings.Contains(s, `"baseURL": "`+modelURL+`"`) || !strings.Contains(s, "{env:CAPM_MODEL_KEY}") ||
					!strings.Contains(s, `"model": "capm/qwen3-coder"`) {
					t.Errorf("opencode.json:\n%s", s)
				}
			}

			// Bundle secrets: env var NAME, injected for the bundle egress hosts.
			_, bind := step(p, "secret", "set-custom", "--sandbox", N, "--host", "api.example.org", "--host", "api.github.com", "--env", "API_TOKEN")
			if bind == nil {
				t.Errorf("no API_TOKEN binding: %v", p.Args)
			} else {
				cmd := flagValues(bind, "--command")
				path := filepath.Join(fx.opts.TempDir, "secrets", "API_TOKEN")
				if !slices.Equal(cmd, []string{"cat " + path}) {
					t.Errorf("--command %v", cmd)
				}
				if f := file(t, p, path); string(f.Content) != sentinelSecret || f.Mode != 0o600 {
					t.Errorf("secret file mode %o", f.Mode)
				}
			}

			// No secret value in any argument.
			for _, a := range p.Args {
				for _, s := range a {
					for _, v := range []string{sentinelSecret, sentinelMCP, sentinelModel} {
						if strings.Contains(s, v) {
							t.Fatalf("secret value in args: %v", a)
						}
					}
				}
			}
			for _, a := range p.Cleanup {
				if strings.Contains(strings.Join(a, " "), "SENTINEL") {
					t.Fatalf("secret in cleanup: %v", a)
				}
			}
			if !hasArgs(p.Cleanup, "rm", "--force", N) {
				t.Errorf("cleanup lacks sandbox rm: %v", p.Cleanup)
			}
			if !hasArgs(p.Cleanup, "mcp", "rm", "--force", srv) {
				t.Errorf("cleanup lacks mcp rm: %v", p.Cleanup)
			}
			if p.Enforced {
				t.Error("plan claims egress enforcement it cannot establish")
			}
			if p.KitRef != tc.kit {
				t.Errorf("KitRef %q", p.KitRef)
			}
		})
	}
}

func TestBuildPlanMissingSecret(t *testing.T) {
	fx := newFixture(t, "claude-code", "2.1.292")
	delete(fx.opts.Secrets, "API_TOKEN")
	_, err := BuildPlan(fx.m, fx.opts)
	if err == nil || !strings.Contains(err.Error(), "API_TOKEN") {
		t.Fatalf("err %v, want one naming API_TOKEN", err)
	}
	if strings.Contains(err.Error(), sentinelMCP) {
		t.Fatal("error leaks a value")
	}
	fx.opts.Secrets["API_TOKEN"] = ""
	if _, err := BuildPlan(fx.m, fx.opts); err == nil || !strings.Contains(err.Error(), "API_TOKEN") {
		t.Fatalf("empty value: err %v", err)
	}
}

func TestMountEscapes(t *testing.T) {
	outside := t.TempDir()
	cases := map[string]func(t *testing.T, work string) string{
		"dotdot": func(t *testing.T, work string) string { return "../escape" },
		"symlink": func(t *testing.T, work string) string {
			if err := os.Symlink(outside, filepath.Join(work, "link")); err != nil {
				t.Fatal(err)
			}
			return "link"
		},
		"nested symlink": func(t *testing.T, work string) string {
			os.Symlink(outside, filepath.Join(work, "workspace", "deep"))
			return "workspace/deep"
		},
		"absolute": func(t *testing.T, work string) string { return outside },
		"missing":  func(t *testing.T, work string) string { return "nope" },
		"colon":    func(t *testing.T, work string) string { os.Mkdir(filepath.Join(work, "a:ro"), 0o755); return "a:ro" },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			fx := newFixture(t, "claude-code", "2.1.292")
			fx.m.Permissions.Mounts = []manifest.Mount{{Path: mk(t, fx.opts.WorkDir), Mode: "read-only"}}
			if _, err := BuildPlan(fx.m, fx.opts); err == nil {
				t.Fatal("expected an error")
			}
			if _, err := Describe(fx.m, fx.opts); err == nil {
				t.Fatal("Describe: expected an error")
			}
		})
	}
}

func TestSecretDirInsideMountRefused(t *testing.T) {
	fx := newFixture(t, "claude-code", "2.1.292")
	fx.opts.TempDir = filepath.Join(fx.opts.WorkDir, "out", "capm-tmp")
	os.Mkdir(fx.opts.TempDir, 0o700)
	if _, err := BuildPlan(fx.m, fx.opts); err == nil || !strings.Contains(err.Error(), "inside") {
		t.Fatalf("err %v", err)
	}
}

func TestContextChecks(t *testing.T) {
	t.Run("symlink escape", func(t *testing.T) {
		fx := newFixture(t, "claude-code", "2.1.292")
		secret := filepath.Join(t.TempDir(), "id_rsa")
		os.WriteFile(secret, []byte("PRIVATE"), 0o600)
		p := filepath.Join(fx.opts.BundleDir, "prompts", "review.md")
		os.Remove(p)
		os.Symlink(secret, p)
		if _, err := BuildPlan(fx.m, fx.opts); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("kit expression", func(t *testing.T) {
		fx := newFixture(t, "opencode", "1.18.33")
		os.WriteFile(filepath.Join(fx.opts.BundleDir, "prompts", "review.md"), []byte("leak ${{ kit.env.HOME }}"), 0o644)
		if _, err := BuildPlan(fx.m, fx.opts); err == nil || !strings.Contains(err.Error(), "${{") {
			t.Fatalf("err %v", err)
		}
	})
}

func TestModelChecks(t *testing.T) {
	fx := newFixture(t, "claude-code", "2.1.292")
	for _, u := range []string{"", "http://models.example.com", "https://u:p@models.example.com", "https://models.example.com:8443", "https://api.anthropic.com"} {
		o := fx.opts
		o.ModelBaseURL = u
		if _, err := BuildPlan(fx.m, o); err == nil {
			t.Errorf("model url %q accepted", u)
		}
	}
	oc := newFixture(t, "opencode", "1.18.33")
	oc.opts.ModelName = ""
	if _, err := BuildPlan(oc.m, oc.opts); err == nil || !strings.Contains(err.Error(), "model") {
		t.Errorf("opencode without model name: %v", err)
	}
	// No key: no key binding, plus a warning.
	fx.opts.ModelKey = ""
	p, err := BuildPlan(fx.m, fx.opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, s := step(p, "secret", "set-custom", "--sandbox", fx.opts.SandboxName, "--host", "models.example.com"); s != nil {
		t.Errorf("key binding without a key: %v", s)
	}
}

func TestWarnings(t *testing.T) {
	fx := newFixture(t, "claude-code", "2.1.292")
	fx.m.Permissions.Egress = append(fx.m.Permissions.Egress, "api.anthropic.com")
	p, err := BuildPlan(fx.m, fx.opts)
	if err != nil {
		t.Fatal(err)
	}
	w := strings.Join(p.Warnings, "\n")
	for _, s := range []string{"toolCalling", "32000", "api.anthropic.com", "openai-compatible"} {
		if !strings.Contains(w, s) {
			t.Errorf("warnings lack %q:\n%s", s, w)
		}
	}
}

func TestNoEgressNoSecretBinding(t *testing.T) {
	fx := newFixture(t, "claude-code", "2.1.292")
	fx.m.Permissions.Egress = nil
	p, err := BuildPlan(fx.m, fx.opts)
	if err != nil {
		t.Fatal(err)
	}
	if _, s := step(p, "secret", "set-custom", "--sandbox", fx.opts.SandboxName, "--env", "API_TOKEN"); s != nil {
		t.Errorf("binding without hosts: %v", s)
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "API_TOKEN") {
		t.Errorf("no warning for unbound secret: %v", p.Warnings)
	}
	spec := file(t, p, filepath.Join(fx.opts.TempDir, "mixin", "spec.yaml"))
	if strings.Contains(string(spec.Content), "network-policy") {
		t.Errorf("empty egress should emit no network-policy:\n%s", spec.Content)
	}
}

func TestBadKitTag(t *testing.T) {
	fx := newFixture(t, "claude-code", "2.1.292")
	fx.m.Base.Version = "2.1/../x"
	if _, err := BuildPlan(fx.m, fx.opts); err == nil {
		t.Fatal("bad tag accepted")
	}
}

func hasArgs(list [][]string, want ...string) bool {
	return slices.ContainsFunc(list, func(a []string) bool { return slices.Equal(a, want) })
}

func TestSecretNameCollision(t *testing.T) {
	for _, name := range []string{"ANTHROPIC_API_KEY", "ANTHROPIC_BASE_URL", "CAPM_MODEL_KEY"} {
		fx := newFixture(t, "claude-code", "2.1.292")
		fx.m.Secrets = append(fx.m.Secrets, manifest.Secret{Name: name})
		fx.opts.Secrets[name] = "x"
		if _, err := Describe(fx.m, fx.opts); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

func TestDescribeChecksContext(t *testing.T) {
	fx := newFixture(t, "claude-code", "2.1.292")
	os.Remove(filepath.Join(fx.opts.BundleDir, "prompts", "review.md"))
	if _, err := Describe(fx.m, fx.opts); err == nil {
		t.Fatal("missing context file accepted before confirmation")
	}
}

func TestMCPNameInjectionRefused(t *testing.T) {
	cases := map[string][]manifest.MCP{
		"comma":     {{Name: "x,notion", URL: "https://mcp.example.com/mcp"}},
		"colon":     {{Name: "a:b", URL: "https://mcp.example.com/mcp", Secret: "GITHUB_TOKEN"}},
		"space":     {{Name: "a b", URL: "https://mcp.example.com/mcp"}},
		"duplicate": {{Name: "gh", URL: "https://mcp.example.com/mcp"}, {Name: "gh", URL: "https://mcp.example.net/mcp"}},
	}
	for name, mcps := range cases {
		t.Run(name, func(t *testing.T) {
			fx := newFixture(t, "claude-code", "2.1.292")
			fx.m.MCP = mcps // bypasses manifest.Validate on purpose
			if err := fx.m.Validate(); err == nil {
				t.Error("manifest.Validate accepted it")
			}
			if _, err := Describe(fx.m, fx.opts); err == nil {
				t.Error("Describe accepted it")
			}
			p, err := BuildPlan(fx.m, fx.opts)
			if err == nil {
				t.Errorf("BuildPlan accepted it: %v", p.Args)
			}
		})
	}
}

func TestStaticMCPOnlyOwnNames(t *testing.T) {
	fx := newFixture(t, "claude-code", "2.1.292")
	fx.m.MCP = append(fx.m.MCP, manifest.MCP{Name: "notion-b", URL: "https://mcp.example.net/mcp"})
	p, err := BuildPlan(fx.m, fx.opts)
	if err != nil {
		t.Fatal(err)
	}
	_, create := step(p, "create")
	vals := flagValues(create, "--static-mcp")
	if len(vals) != 1 {
		t.Fatalf("--static-mcp %v", vals)
	}
	got := strings.Split(vals[0], ",")
	want := []string{fx.opts.SandboxName + "-gh", fx.opts.SandboxName + "-notion-b"}
	if !slices.Equal(got, want) {
		t.Errorf("--static-mcp names %v, want %v", got, want)
	}
	for _, n := range got {
		if n == "notion" || !strings.HasPrefix(n, fx.opts.SandboxName+"-") {
			t.Errorf("foreign MCP name %q in --static-mcp", n)
		}
	}
}
