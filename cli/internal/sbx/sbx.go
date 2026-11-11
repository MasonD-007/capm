// Package sbx turns a capm manifest into the ordered Docker Sandboxes (sbx)
// invocations that run it. Everything sbx-specific (commands, flags, kit YAML,
// in-sandbox paths) lives here, behind BuildPlan, which is pure data so it can
// be tested without sbx.
//
// NOTHING here has been run against a real sandbox. It follows
// docs/sbx-findings.md, which was written without a Docker login. Comments
// tagged "findings §N" / "Q#" / "V#" point at the section, the answers-table
// row and the verify step that would confirm each assumption.
package sbx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/MasonD-007/capm/manifest"
)

// Bin is the sbx executable every Plan.Args entry is passed to.
const Bin = "sbx"

// Options are the installer-side inputs to a plan.
type Options struct {
	WorkDir     string // host directory mount paths are relative to
	BundleDir   string // unpacked bundle (capm.yaml and context files)
	TempDir     string // capm-owned 0700 directory for generated files; removed by the caller
	SandboxName string // unique per run

	ModelBaseURL string // https URL of the installer's model endpoint
	ModelKey     string // optional; bound via the sbx secret proxy
	ModelName    string // model id; required for opencode

	Secrets map[string]string // declared secret NAME -> value

	// Global sbx secrets on this machine (`sbx secret ls --global --quiet`,
	// see ParseSecretList). GlobalSecretsChecked is false when that listing
	// failed. A global anthropic secret is injected by the sbx proxy on
	// requests to api.anthropic.com (findings Q4), which the base agent can
	// reach, so capm refuses unless AllowGlobalAnthropicSecret is set.
	GlobalSecrets              []string
	GlobalSecretsChecked       bool
	AllowGlobalAnthropicSecret bool
}

// SecretRoute says where the sbx proxy or MCP gateway delivers one secret.
type SecretRoute struct {
	Name  string   // declared secret NAME, or "model key"
	Hosts []string // destination hosts
	Via   string   // how it gets there
}

// File is a file the caller must write before running the plan (and remove
// afterwards, by removing Options.TempDir).
type File struct {
	Path    string
	Content []byte
	Mode    os.FileMode
}

// Mount is a resolved manifest mount.
type Mount struct {
	Path     string // as written in the manifest
	HostPath string // symlink-resolved, inside WorkDir
	ReadOnly bool
}

// Info is everything shown to the installer before secrets are collected.
type Info struct {
	KitRef         string
	Egress         []string // bundle egress; exactly EnforcedSummary().Egress
	BaseAgentHosts []string // manifest.BaseAgentHosts; empty when broad
	BaseAgentBroad bool     // the kit's own list is broad and not enumerated
	BaseAgentNote  string
	ModelHost      string
	SecretRoutes   []SecretRoute // per secret: destination hosts
	Mounts         []Mount
	ContextDest    string // in-sandbox path of the delivered context, "" if none
	Enforced       bool
	EnforcementMsg string
	Warnings       []string

	ctxBody string // concatenated context files for agent-context@2
}

// Plan is the ordered sbx invocations for one run.
type Plan struct {
	Info
	SandboxName string
	// Args are the sbx invocations, in order, without the binary name.
	// Secret values never appear here.
	Args [][]string
	// Stdin maps an index in Args to what is fed on that command's stdin.
	Stdin map[int]string
	// Verify maps an index in Args to a check of that command's stdout; such
	// commands are run with Runner.Output and the run aborts if the check
	// fails.
	Verify map[int]func(stdout []byte) error
	// Attach is the index of the interactive agent session.
	Attach int
	// Cleanup runs after the plan, whatever happened, best effort.
	Cleanup [][]string
	// Env is the non-secret environment set in the sandbox (as -e KEY=VALUE).
	Env   map[string]string
	Files []File
}

// Runner executes a command. RunWithStdin feeds stdin (used for secrets);
// Output returns stdout (used for read-only queries and checks).
type Runner interface {
	Run(ctx context.Context, name string, args ...string) error
	RunWithStdin(ctx context.Context, stdin io.Reader, name string, args ...string) error
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner runs commands with os/exec, wired to the given streams.
type ExecRunner struct {
	Stdin          io.Reader
	Stdout, Stderr io.Writer
}

func (r ExecRunner) Run(ctx context.Context, name string, args ...string) error {
	return r.RunWithStdin(ctx, r.Stdin, name, args...)
}

func (r ExecRunner) RunWithStdin(ctx context.Context, stdin io.Reader, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, r.Stdout, r.Stderr
	return cmd.Run()
}

func (r ExecRunner) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stderr = r.Stderr
	return cmd.Output()
}

// agentSpec is what capm knows about a base agent's sbx kit. The kit's own
// egress comes from manifest.BaseAgentHosts, the one shared table.
type agentSpec struct {
	kitRepo   string
	ctxDir    string // findings Q6 targets; kit-spec agent-context-placement.md
	ctxFile   string
	hostsNote string
	keyEnv    string // env var the model key placeholder is bound to
}

var agents = map[string]agentSpec{
	"claude-code": {
		// findings §6 / Q5: pinned v3 workload kit by OCI ref. V0.
		kitRepo: "docker.io/docker/sbx-kit-claude",
		ctxDir:  "/home/agent/.claude", ctxFile: "CLAUDE.md", // findings Q6. V7.
		// findings §3: the claude kit's own allow list (all :443). V5.
		hostsNote: "set by the sbx claude kit; unverified",
		// findings Q4: Claude Code reads ANTHROPIC_API_KEY; placeholder via set-custom. V6.
		keyEnv: "ANTHROPIC_API_KEY",
	},
	"opencode": {
		kitRepo: "docker.io/docker/sbx-kit-opencode",                  // findings §6 / Q5. V0.
		ctxDir:  "/home/agent/.config/opencode", ctxFile: "AGENTS.md", // findings Q6. V7.
		// findings §3: "opencode adds a broad multi-provider list"; not enumerated.
		hostsNote: manifest.BroadBaseHostsNotice,
		// capm's own name; opencode.json reads it via {env:...}. Unverified (findings §7).
		keyEnv: "CAPM_MODEL_KEY",
	},
}

// findings Q4: the built-in anthropic secret is injected for these hosts, so a
// set-custom model key for the same host would compete with it. Refused. V6.
var anthropicInjectHosts = []string{"api.anthropic.com", "mcp-proxy.anthropic.com"}

var (
	tagRe     = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$`) // OCI tag grammar
	safePath  = regexp.MustCompile(`^[A-Za-z0-9/._-]+$`)
	mcpNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`) // same rule as manifest.Validate
	modelIDRe = regexp.MustCompile(`^[A-Za-z0-9._:/@-]{1,200}$`)
)

// kit-spec agent-context@2: refuse above 512 KiB, warn above 64 KiB.
const (
	ctxWarnBytes = 64 << 10
	ctxMaxBytes  = 512 << 10
)

// Describe validates everything except secret values and returns what the
// installer must be shown before confirming.
func Describe(m *manifest.Manifest, o Options) (Info, error) {
	var info Info
	ag, ok := agents[m.Base.Agent]
	if !ok {
		return info, fmt.Errorf("unsupported base agent %q", m.Base.Agent)
	}
	// Ruling: base.version maps straight to the kit tag; sbx rejects unknown tags.
	if !tagRe.MatchString(m.Base.Version) {
		return info, fmt.Errorf("base.version %q is not a valid kit tag", m.Base.Version)
	}
	// Re-checked here (manifest.Validate does too) because MCP names reach
	// comma-split --static-mcp and colon-separated mcp:<server>:<key> args:
	// a name like "x,notion" would attach the user's own MCP server.
	seen := map[string]bool{}
	for _, c := range m.MCP {
		if !mcpNameRe.MatchString(c.Name) {
			return info, fmt.Errorf("MCP server name %q must match %s", c.Name, mcpNameRe)
		}
		if seen[c.Name] {
			return info, fmt.Errorf("duplicate MCP server name %q", c.Name)
		}
		seen[c.Name] = true
	}
	sum := m.EnforcedSummary()
	info.KitRef = ag.kitRepo + ":" + m.Base.Version
	info.Egress = sum.Egress
	info.BaseAgentHosts, info.BaseAgentBroad = manifest.BaseAgentHosts(m.Base.Agent)
	info.BaseAgentNote = ag.hostsNote

	for _, h := range sum.Egress {
		if slices.Contains(info.BaseAgentHosts, h) {
			info.Warnings = append(info.Warnings, fmt.Sprintf("bundle egress lists %s, which the base agent's kit already allows", h))
		}
	}

	host, err := modelHost(o.ModelBaseURL)
	if err != nil {
		return info, err
	}
	if m.Base.Agent == "claude-code" && slices.Contains(anthropicInjectHosts, host) {
		return info, fmt.Errorf("model endpoint host %s is where sbx injects its own anthropic secret; use sbx's built-in claude setup instead (findings Q4)", host)
	}
	info.ModelHost = host
	if m.Base.Agent == "opencode" && !modelIDRe.MatchString(o.ModelName) {
		return info, errors.New("opencode needs a model name (--model or CAPM_MODEL)")
	}

	// I3 / findings Q4: a global `anthropic` secret is injected by the sbx
	// proxy into requests to api.anthropic.com. The claude kit allows that
	// host and opencode's broad list presumably does too, so the bundle
	// could spend the installer's Anthropic credentials even when they
	// supplied another model endpoint.
	anthropicReachable := info.BaseAgentBroad || slices.Contains(info.BaseAgentHosts, "api.anthropic.com")
	if anthropicReachable && !o.AllowGlobalAnthropicSecret {
		if !o.GlobalSecretsChecked {
			return info, errors.New("could not list global sbx secrets (`sbx secret ls --global`) to check for an `anthropic` secret the bundle could use via api.anthropic.com; " +
				"fix sbx or pass --allow-global-anthropic-secret")
		}
		if hasAnthropic(o.GlobalSecrets) {
			return info, errors.New("a global sbx `anthropic` secret is stored on this machine; sbx injects it into requests to api.anthropic.com, which this sandbox can reach, " +
				"so the bundle could use your Anthropic credentials. Remove it (`sbx secret rm anthropic`) or pass --allow-global-anthropic-secret")
		}
	}
	if o.GlobalSecretsChecked && len(o.GlobalSecrets) > 0 {
		names := make([]string, len(o.GlobalSecrets))
		for i, n := range o.GlobalSecrets {
			names[i] = manifest.DisplaySafe(n)
		}
		info.Warnings = append(info.Warnings, fmt.Sprintf(
			"global sbx secrets stored on this machine: %s; sbx may inject them into requests this sandbox makes to their services' hosts (egress is not enforced)",
			strings.Join(names, ", ")))
	} else if !o.GlobalSecretsChecked {
		info.Warnings = append(info.Warnings, "could not list global sbx secrets; any stored there may be injected into requests this sandbox makes to their services' hosts")
	}

	if info.Mounts, err = resolveMounts(m.Permissions.Mounts, o.WorkDir); err != nil {
		return info, err
	}
	if o.TempDir == "" || !safePath.MatchString(o.TempDir) || !filepath.IsAbs(o.TempDir) {
		return info, fmt.Errorf("temporary directory %q must be an absolute path of plain characters", o.TempDir)
	}
	// set-custom --help: secret helpers must stay outside sandbox mounts.
	tmpReal, err := filepath.EvalSymlinks(o.TempDir)
	if err != nil {
		return info, err
	}
	for _, mt := range info.Mounts {
		if within(mt.HostPath, tmpReal) {
			return info, fmt.Errorf("mount %s would expose capm's temporary directory %s (it is inside the mount); choose another --workdir or TMPDIR", mt.Path, tmpReal)
		}
	}

	// Names capm itself sets in the sandbox environment.
	for _, s := range m.Secrets {
		if s.Name == ag.keyEnv || strings.HasPrefix(s.Name, "ANTHROPIC_") || strings.HasPrefix(s.Name, "CAPM_") {
			return info, fmt.Errorf("secret %s collides with an environment variable capm sets for the model endpoint", s.Name)
		}
	}

	if len(m.Context) > 0 {
		info.ContextDest = ag.ctxDir + "/" + ag.ctxFile
		var warn string
		if info.ctxBody, warn, err = contextBody(m.Context, o.BundleDir); err != nil {
			return info, err
		}
		if warn != "" {
			info.Warnings = append(info.Warnings, warn)
		}
	}

	// Ruling: model requirements are advisory.
	if r := m.Model.Requires; r.ToolCalling || r.MinContextTokens > 0 {
		info.Warnings = append(info.Warnings, fmt.Sprintf(
			"capm cannot check your model: the bundle wants toolCalling=%t, minContextTokens=%d", r.ToolCalling, r.MinContextTokens))
	}
	if m.Base.Agent == "claude-code" && m.Model.API != "anthropic" {
		info.Warnings = append(info.Warnings, fmt.Sprintf(
			"the bundle declares model.api %q, but Claude Code speaks the Anthropic Messages API; your endpoint must accept it", m.Model.API))
	}
	if o.ModelKey == "" {
		info.Warnings = append(info.Warnings, "no model key given; requests to your model endpoint carry none")
	}
	// I4: where each secret goes. A secret named by an mcp[].secret travels
	// only to that MCP server through the host gateway and is not bound to
	// egress hosts; any other secret is bound to every bundle egress host.
	mcpHosts := mcpSecretHosts(m)
	if o.ModelKey != "" {
		info.SecretRoutes = append(info.SecretRoutes, SecretRoute{Name: "model key", Hosts: []string{host}, Via: "sbx proxy, as " + ag.keyEnv})
	}
	for _, s := range m.Secrets {
		if hs, ok := mcpHosts[s.Name]; ok {
			info.SecretRoutes = append(info.SecretRoutes, SecretRoute{Name: s.Name, Hosts: hs, Via: "host MCP gateway only"})
			continue
		}
		if len(sum.Egress) == 0 {
			info.Warnings = append(info.Warnings, fmt.Sprintf("secret %s is not bound to an environment variable: the bundle has no egress hosts for sbx to inject it into", s.Name))
			continue
		}
		info.SecretRoutes = append(info.SecretRoutes, SecretRoute{Name: s.Name, Hosts: sum.Egress, Via: "sbx proxy, as env " + s.Name})
	}

	// findings §2 / Q1 and kit-spec network-policy@2 "Composition": allow
	// entries union across kits, so a mixin can only widen sbx's default
	// (broad) policy. Exact-host egress needs a deny-all global baseline,
	// which capm does not impose on the machine, and checking the effective
	// policy (`sbx policy ls NAME`) needs an output format no one has seen
	// (V5). So enforcement cannot be established; never claim it.
	info.Enforced = false
	info.EnforcementMsg = "NOT ENFORCED: sbx's default network policy is a broad allowlist that kit rules can only widen, " +
		"and capm cannot check the sandbox's effective policy, so the sandbox may reach hosts beyond the lists above " +
		"(exact-host egress needs `sbx policy init deny-all`, which changes every sandbox on this machine; capm does not do that for you)"
	return info, nil
}

// BuildPlan returns the sbx invocations that run m. It errors if any declared
// secret has no value.
func BuildPlan(m *manifest.Manifest, o Options) (Plan, error) {
	info, err := Describe(m, o)
	if err != nil {
		return Plan{}, err
	}
	for _, s := range m.Secrets {
		if o.Secrets[s.Name] == "" {
			return Plan{}, fmt.Errorf("no value for secret %s", s.Name)
		}
	}
	ag := agents[m.Base.Agent]
	N := o.SandboxName
	if !regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,62}$`).MatchString(N) {
		return Plan{}, fmt.Errorf("invalid sandbox name %q", N)
	}
	p := Plan{Info: info, SandboxName: N, Stdin: map[int]string{}, Env: map[string]string{}, Verify: map[int]func([]byte) error{}}
	add := func(stdin string, args ...string) {
		if stdin != "" {
			p.Stdin[len(p.Args)] = stdin
		}
		p.Args = append(p.Args, args)
	}
	workspace := filepath.Join(o.TempDir, "workspace")
	secretsDir := filepath.Join(o.TempDir, "secrets")
	mixinDir := filepath.Join(o.TempDir, "mixin")
	mixinZip := filepath.Join(o.TempDir, "mixin.zip")
	secretFile := func(name, value string) string {
		path := filepath.Join(secretsDir, name)
		p.Files = append(p.Files, File{Path: path, Content: []byte(value), Mode: 0o600})
		return path
	}

	// 1. Generated v3 mixin: bundle egress + context (findings "Composed
	//    capm run sequence" step 1; Q6 route (a)). Shape from kit-spec
	//    SPEC-v3 §4 and capabilities network-policy@2 / agent-context@2. V2.
	spec, err := mixinSpec(m, info.Egress, ag, info.ctxBody)
	if err != nil {
		return Plan{}, err
	}
	p.Files = append(p.Files, File{Path: filepath.Join(mixinDir, "spec.yaml"), Content: spec, Mode: 0o644})
	// `sbx kit pack DIRECTORY -o FILE.zip` (kit pack --help).
	add("", "kit", "pack", mixinDir, "--output", mixinZip)

	// The capm-owned primary workspace (findings Q2: the first path is the
	// read-write workspace). Using an empty temp dir keeps the installer's
	// workdir from being mounted wholesale. V3/V4.
	p.Files = append(p.Files, File{Path: filepath.Join(workspace, ".capm"), Content: []byte("capm workspace for " + m.Metadata.Name + "\n"), Mode: 0o644})

	// 2. Secrets, scoped to this sandbox (findings Q3, sequence step 2).
	//    `--command 'cat FILE'` keeps values out of argv (set-custom --help:
	//    helper paths must be absolute and outside writable mounts). Whether
	//    --sandbox works before the sandbox exists is V2; whether the env var
	//    holds a placeholder is V6.
	placeholder := func(name string) string { return N + "-" + strings.ToLower(strings.ReplaceAll(name, "_", "-")) }
	customSecret := func(env, value string, hosts []string) {
		args := []string{"secret", "set-custom", "--sandbox", N}
		for _, h := range hosts {
			args = append(args, "--host", h)
		}
		args = append(args, "--env", env, "--placeholder", placeholder(env), "--command", "cat "+secretFile(env, value))
		add("", args...)
		p.Cleanup = append(p.Cleanup, []string{"secret", "rm", "--placeholder", placeholder(env), "--force"})
	}
	if o.ModelKey != "" {
		customSecret(ag.keyEnv, o.ModelKey, []string{info.ModelHost})
	}
	// Ruling: each declared secret NAME is bound as env var NAME, injected by
	// the proxy for the bundle's egress hosts (set-custom needs --host).
	// MCP secrets are skipped (I4): they reach only their MCP server, via
	// the gateway (step 3).
	mcpHosts := mcpSecretHosts(m)
	if len(info.Egress) > 0 {
		for _, s := range m.Secrets {
			if _, mcpOnly := mcpHosts[s.Name]; !mcpOnly {
				customSecret(s.Name, o.Secrets[s.Name], info.Egress)
			}
		}
	}

	// 3. MCP servers via the host gateway, not sandbox egress (findings §1,
	//    Q7; sequence step 3). Global registry names, so namespaced by the
	//    unique sandbox name (findings §5). V1, V8.
	//    C2: `--url` also accepts registry and server.json URLs that resolve
	//    to an image-backed stdio server running on the host. Per `sbx mcp
	//    add --help` (v0.48), an add carrying --header "fails rather than
	//    dropping them" when the URL resolves to stdio, so every add carries
	//    a header; and `sbx mcp inspect --json` must then show a remote
	//    endpoint at exactly the manifest URL, else the run aborts (and
	//    cleanup removes the registration). Both unverified (V1).
	var mcpNames []string
	for _, c := range m.MCP {
		srv := N + "-" + c.Name
		args := []string{"mcp", "add", srv, "--url", c.URL, "--skip-auth", "--header", "X-Capm-Bundle: " + N}
		key := ""
		if c.Secret != "" {
			key = strings.ToLower(strings.ReplaceAll(c.Secret, "_", "-"))
			args = append(args, "--header", "Authorization: Bearer ${"+key+"}")
		}
		add("", args...)
		p.Cleanup = append(p.Cleanup, []string{"mcp", "rm", "--force", srv})
		name, want := c.Name, c.URL
		p.Verify[len(p.Args)] = func(out []byte) error {
			if err := verifyRemoteMCP(out, want); err != nil {
				return fmt.Errorf("MCP server %s: %w; aborting", name, err)
			}
			return nil
		}
		add("", "mcp", "inspect", srv, "--json")
		if key != "" {
			// `sbx secret set mcp:<server>:<placeholder>` reads stdin (mcp add --help).
			add(o.Secrets[c.Secret], "secret", "set", "mcp:"+srv+":"+key)
			p.Cleanup = append(p.Cleanup, []string{"secret", "rm", "mcp:" + srv + ":" + key, "--force"})
		}
		mcpNames = append(mcpNames, srv)
	}

	// 4. The installer's model host, for this sandbox only (findings §7, Q4;
	//    sequence step 4). Port fixed to 443 (findings §2). V2, V5.
	add("", "policy", "allow", "network", "--sandbox", N, info.ModelHost+":443")

	// Agent-specific model wiring (findings §7, Q4). V6.
	switch m.Base.Agent {
	case "claude-code":
		p.Env["ANTHROPIC_BASE_URL"] = o.ModelBaseURL
		if o.ModelName != "" {
			p.Env["ANTHROPIC_MODEL"] = o.ModelName
		}
	case "opencode":
		oc, err := opencodeConfig(m.Model.API, o.ModelBaseURL, o.ModelName, ag.keyEnv, o.ModelKey != "")
		if err != nil {
			return Plan{}, err
		}
		p.Files = append(p.Files, File{Path: filepath.Join(workspace, "opencode.json"), Content: oc, Mode: 0o644})
	}

	// 5. Create: pinned base + workspace + mounts (:ro suffix for read-only,
	//    findings Q2) + mixin + env + MCP set + name. Sequence step 5. V2-V4.
	create := []string{"create", info.KitRef, workspace}
	for _, mt := range info.Mounts {
		if mt.ReadOnly {
			create = append(create, mt.HostPath+":ro")
		} else {
			create = append(create, mt.HostPath)
		}
	}
	// I3: `sbx create --skills` defaults to readonly, which links the
	// installer's host skills store into the sandbox (create --help, v0.48).
	create = append(create, "--kit", mixinZip, "--skills", "off")
	envKeys := make([]string, 0, len(p.Env))
	for k := range p.Env {
		envKeys = append(envKeys, k)
	}
	slices.Sort(envKeys)
	for _, k := range envKeys {
		create = append(create, "-e", k+"="+p.Env[k])
	}
	if len(mcpNames) > 0 {
		create = append(create, "--static-mcp", strings.Join(mcpNames, ","))
	}
	create = append(create, "--name", N)
	add("", create...)
	// Removing the sandbox first; scoped secrets/policy presumably go with it,
	// but they are removed explicitly too (unverified).
	p.Cleanup = append([][]string{{"rm", "--force", N}}, p.Cleanup...)
	p.Cleanup = append(p.Cleanup, []string{"policy", "rm", "network", "--sandbox", N, "--resource", info.ModelHost + ":443"})

	// 7. Attach (`sbx run --name SANDBOX`, create --help). Step 6 (sbx cp) is
	//    unused: all context goes through the mixin.
	p.Attach = len(p.Args)
	add("", "run", "--name", N)
	return p, nil
}

func modelHost(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("no model endpoint: pass --model-url or set CAPM_MODEL_URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New("model endpoint must be an https URL without credentials, query or fragment")
	}
	if p := u.Port(); p != "" && p != "443" {
		return "", errors.New("model endpoint must use port 443 (sbx egress rules are host:443)")
	}
	return strings.ToLower(u.Hostname()), nil
}

func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && filepath.IsLocal(rel)
}

func jsonIndent(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	err := enc.Encode(v)
	return b.Bytes(), err
}

// resolveMounts resolves each mount against workdir, following symlinks, and
// refuses anything that ends up outside it.
func resolveMounts(ms []manifest.Mount, workdir string) ([]Mount, error) {
	if workdir == "" {
		return nil, errors.New("no working directory")
	}
	root, err := filepath.Abs(workdir)
	if err == nil {
		root, err = filepath.EvalSymlinks(root)
	}
	if err != nil {
		return nil, fmt.Errorf("working directory: %w", err)
	}
	out := make([]Mount, 0, len(ms))
	for _, mt := range ms {
		if mt.Path == "" || filepath.IsAbs(mt.Path) || !filepath.IsLocal(mt.Path) {
			return nil, fmt.Errorf("mount %s must be a relative path inside %s", mt.Path, root)
		}
		real, err := filepath.EvalSymlinks(filepath.Join(root, mt.Path))
		if err != nil {
			return nil, fmt.Errorf("mount %s: %w", mt.Path, err)
		}
		if !within(root, real) {
			return nil, fmt.Errorf("mount %s resolves to %s, outside %s", mt.Path, real, root)
		}
		// sbx path syntax: PATH[:ro], comma-separated lists elsewhere.
		if strings.ContainsAny(real, ":,") {
			return nil, fmt.Errorf("mount %s: path %s contains ':' or ',' which sbx cannot express", mt.Path, real)
		}
		var ro bool
		switch mt.Mode {
		case "read-only":
			ro = true
		case "read-write":
		default:
			return nil, fmt.Errorf("mount %s: unknown mode %q", mt.Path, mt.Mode)
		}
		out = append(out, Mount{Path: mt.Path, HostPath: real, ReadOnly: ro})
	}
	return out, nil
}

// contextBody concatenates the bundle's context files for agent-context@2.
func contextBody(paths []string, bundleDir string) (string, string, error) {
	if len(paths) == 0 {
		return "", "", nil
	}
	root, err := filepath.EvalSymlinks(bundleDir)
	if err != nil {
		return "", "", fmt.Errorf("bundle directory: %w", err)
	}
	var b strings.Builder
	for i, p := range paths {
		if !filepath.IsLocal(p) {
			return "", "", fmt.Errorf("context file %s is outside the bundle", p)
		}
		real, err := filepath.EvalSymlinks(filepath.Join(root, p))
		if err != nil {
			return "", "", fmt.Errorf("context file %s: %w", p, err)
		}
		if !within(root, real) {
			return "", "", fmt.Errorf("context file %s resolves outside the bundle", p)
		}
		st, err := os.Stat(real)
		if err != nil || !st.Mode().IsRegular() {
			return "", "", fmt.Errorf("context file %s is not a regular file", p)
		}
		data, err := os.ReadFile(real)
		if err != nil {
			return "", "", err
		}
		// Kit expansion substitutes ${{ ... }} in content and has no escape
		// (kit-spec SPEC-v3 §6, agent-context@2 "expansion").
		if strings.Contains(string(data), "${{") {
			return "", "", fmt.Errorf("context file %s contains \"${{\", which sbx kits would expand", p)
		}
		if i > 0 {
			b.WriteString("\n\n")
		}
		fmt.Fprintf(&b, "<!-- capm context file: %s -->\n", p)
		b.Write(data)
	}
	var warn string
	if b.Len() > ctxMaxBytes {
		return "", "", fmt.Errorf("context files total %d bytes; sbx refuses more than %d", b.Len(), ctxMaxBytes)
	}
	if b.Len() > ctxWarnBytes {
		warn = fmt.Sprintf("context files total %d bytes; sbx warns above %d", b.Len(), ctxWarnBytes)
	}
	return b.String(), warn, nil
}

type kitCap struct {
	Type   string `yaml:"type"`
	Config any    `yaml:"config"`
}

type kitDoc struct {
	SchemaVersion string   `yaml:"schemaVersion"`
	Kind          string   `yaml:"kind"`
	DisplayName   string   `yaml:"displayName"`
	Description   string   `yaml:"description"`
	Capabilities  []kitCap `yaml:"capabilities,omitempty"`
}

// mixinSpec renders the generated kit's spec.yaml. Unverified end to end (V2):
// the shape follows SPEC-v3 §4 (no name field; strict decoding).
func mixinSpec(m *manifest.Manifest, egress []string, ag agentSpec, ctx string) ([]byte, error) {
	d := kitDoc{SchemaVersion: "3", Kind: "mixin",
		DisplayName: "capm " + m.Metadata.Name + "@" + m.Metadata.Version,
		Description: "Generated by capm run: bundle egress and context"}
	if len(egress) > 0 {
		allow := make([]string, len(egress))
		for i, h := range egress {
			allow[i] = h + ":443"
		}
		d.Capabilities = append(d.Capabilities, kitCap{Type: "com.docker.sandbox/network-policy@2",
			Config: map[string]any{"runtime": map[string]any{"allow": allow}}})
	}
	if ctx != "" {
		d.Capabilities = append(d.Capabilities, kitCap{Type: "com.docker.sandbox/agent-context@2",
			Config: map[string]any{"filename": ag.ctxFile, "directory": ag.ctxDir, "content": ctx}})
	}
	body, err := yaml.Marshal(d)
	if err != nil {
		return nil, err
	}
	return append([]byte("# syntax=docker/sandbox-kit:3\n"), body...), nil
}

// opencodeConfig is the project-level opencode.json provider block (findings
// §7, Q4: OpenCode reads it from the workspace). Unverified; V6.
func opencodeConfig(api, baseURL, model, keyEnv string, haveKey bool) ([]byte, error) {
	npm := "@ai-sdk/openai-compatible"
	if api == "anthropic" {
		npm = "@ai-sdk/anthropic"
	}
	opts := map[string]any{"baseURL": baseURL}
	if haveKey {
		opts["apiKey"] = "{env:" + keyEnv + "}"
	}
	cfg := map[string]any{
		"$schema": "https://opencode.ai/config.json",
		"provider": map[string]any{"capm": map[string]any{
			"npm": npm, "name": "Model endpoint supplied via capm",
			"options": opts,
			"models":  map[string]any{model: map[string]any{"name": model}},
		}},
		"model": "capm/" + model,
	}
	return jsonIndent(cfg)
}

// mcpSecretHosts maps each secret named by an mcp[].secret to the hosts of
// the MCP servers that use it.
func mcpSecretHosts(m *manifest.Manifest) map[string][]string {
	out := map[string][]string{}
	for _, c := range m.MCP {
		if c.Secret == "" {
			continue
		}
		h, _ := manifest.MCPHost(c.URL)
		if !slices.Contains(out[c.Secret], h) {
			out[c.Secret] = append(out[c.Secret], h)
		}
	}
	return out
}

// ParseSecretList reads `sbx secret ls --quiet` output: one name per line.
// The format is from the help text ("Only display secret names") and is
// unverified.
func ParseSecretList(out []byte) []string {
	var names []string
	for _, l := range strings.Split(string(out), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			names = append(names, l)
		}
	}
	return names
}

func hasAnthropic(names []string) bool {
	for _, n := range names {
		if f := strings.Fields(n); len(f) > 0 && strings.EqualFold(f[0], "anthropic") {
			return true
		}
	}
	return false
}

// verifyRemoteMCP checks `sbx mcp inspect NAME --json` output. Its schema is
// undocumented (unverified, V1), so the check fails closed: the output must
// be JSON; no field may describe a local/stdio server (command, args, image,
// packages, local, ...; or a type/transport naming stdio, local, oci, docker,
// image); and at least one url/endpoint field must exist, every one equal to
// want exactly. Errors never echo sbx's raw output.
func verifyRemoteMCP(out []byte, want string) error {
	var v any
	if err := json.Unmarshal(out, &v); err != nil {
		return errors.New("could not read `sbx mcp inspect --json` output, so capm cannot confirm it is a remote server")
	}
	localKeys := map[string]bool{"command": true, "args": true, "image": true, "package": true, "packages": true,
		"dir": true, "local": true, "docker": true, "oci": true, "registrytype": true, "stdio": true}
	typeKeys := map[string]bool{"type": true, "transport": true, "transporttype": true, "kind": true, "servertype": true, "mode": true}
	urlKeys := map[string]bool{"url": true, "endpoint": true, "remoteurl": true, "serverurl": true, "endpointurl": true}
	var urls []string
	local := false
	var walk func(key string, v any)
	walk = func(key string, v any) {
		k := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(key))
		if localKeys[k] && !empty(v) {
			local = true
		}
		if str, ok := v.(string); ok {
			if typeKeys[k] {
				t := strings.ToLower(str)
				for _, bad := range []string{"stdio", "local", "oci", "docker", "image", "command"} {
					if strings.Contains(t, bad) {
						local = true
					}
				}
			}
			if urlKeys[k] {
				urls = append(urls, str)
			}
		}
		switch t := v.(type) {
		case map[string]any:
			for kk, vv := range t {
				walk(kk, vv)
			}
		case []any:
			for _, vv := range t {
				walk(key, vv)
			}
		}
	}
	walk("", v)
	if local {
		return errors.New("sbx registered it as a local (non-remote) server")
	}
	if len(urls) == 0 {
		return errors.New("`sbx mcp inspect` shows no endpoint URL, so capm cannot confirm it is the declared remote server")
	}
	for _, u := range urls {
		if u != want {
			return errors.New("sbx registered an endpoint other than the URL the manifest declares")
		}
	}
	return nil
}

func empty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case bool:
		return !t
	case float64:
		return t == 0
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return false
}
