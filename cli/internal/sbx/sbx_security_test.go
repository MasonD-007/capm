package sbx

import (
	"slices"
	"strings"
	"testing"

	"github.com/MasonD-007/capm/manifest"
)

// C2: every `mcp add` carries a header, so sbx refuses a URL that resolves
// to a stdio (image-backed) server instead of registering it.
func TestEveryMCPAddCarriesHeader(t *testing.T) {
	fx := newFixture(t, "claude-code", "2.1.292")
	fx.m.MCP = append(fx.m.MCP, manifest.MCP{Name: "plain", URL: "https://mcp.example.net/mcp"})
	p, err := BuildPlan(fx.m, fx.opts)
	if err != nil {
		t.Fatal(err)
	}
	adds := steps(p, "mcp", "add")
	if len(adds) != 2 {
		t.Fatalf("mcp add steps %v", adds)
	}
	N := fx.opts.SandboxName
	for _, a := range adds {
		h := flagValues(a, "--header")
		if !slices.Contains(h, "X-Capm-Bundle: "+N) {
			t.Errorf("mcp add without bundle header: %v", a)
		}
	}
	if h := flagValues(adds[0], "--header"); !slices.Contains(h, "Authorization: Bearer ${github-token}") {
		t.Errorf("secret header lost: %v", adds[0])
	}
}

// C2: each registration is checked with `sbx mcp inspect` before anything
// else runs.
func TestMCPAddIsFollowedByInspectCheck(t *testing.T) {
	fx := newFixture(t, "claude-code", "2.1.292")
	p, err := BuildPlan(fx.m, fx.opts)
	if err != nil {
		t.Fatal(err)
	}
	srv := fx.opts.SandboxName + "-gh"
	i, _ := step(p, "mcp", "add")
	if i < 0 || i+1 >= len(p.Args) || !slices.Equal(p.Args[i+1], []string{"mcp", "inspect", srv, "--json"}) {
		t.Fatalf("step after mcp add: %v", p.Args)
	}
	check := p.Verify[i+1]
	if check == nil {
		t.Fatal("no verification for mcp inspect")
	}
	if err := check([]byte(`{"name":"` + srv + `","type":"remote","url":"https://mcp.example.com/mcp"}`)); err != nil {
		t.Errorf("good remote rejected: %v", err)
	}
	if err := check([]byte(`{"name":"` + srv + `","type":"stdio","image":"docker.io/evil/x"}`)); err == nil {
		t.Error("stdio server accepted")
	}
	ci, _ := step(p, "create")
	if ci < i+1 {
		t.Errorf("create before the MCP check: %v", p.Args)
	}
}

func TestVerifyRemoteMCP(t *testing.T) {
	const want = "https://mcp.example.com/mcp"
	ok := map[string]string{
		"flat":   `{"name":"s","type":"remote","url":"https://mcp.example.com/mcp","headers":{"X-Capm-Bundle":"n"}}`,
		"nested": `{"name":"s","remote":{"transport":"streamable-http","url":"https://mcp.example.com/mcp"}}`,
		"array":  `[{"name":"s","url":"https://mcp.example.com/mcp"}]`,
	}
	for name, out := range ok {
		if err := verifyRemoteMCP([]byte(out), want); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	bad := map[string]string{
		"stdio type":     `{"type":"stdio","url":"https://mcp.example.com/mcp"}`,
		"command":        `{"url":"https://mcp.example.com/mcp","command":"docker","args":["run","x"]}`,
		"image":          `{"url":"https://mcp.example.com/mcp","image":"docker.io/evil/x:1"}`,
		"oci package":    `{"url":"https://mcp.example.com/mcp","packages":[{"registryType":"oci","identifier":"x"}]}`,
		"local":          `{"url":"https://mcp.example.com/mcp","local":true}`,
		"other url":      `{"type":"remote","url":"https://evil.example.com/mcp"}`,
		"two urls":       `{"type":"remote","url":"https://mcp.example.com/mcp","remote":{"url":"https://evil.example.com/mcp"}}`,
		"no url":         `{"type":"remote","name":"s"}`,
		"not json":       `NAME TYPE URL`,
		"empty":          ``,
		"trailing slash": `{"type":"remote","url":"https://mcp.example.com/mcp/"}`,
	}
	for name, out := range bad {
		err := verifyRemoteMCP([]byte(out), want)
		if err == nil {
			t.Errorf("%s accepted", name)
			continue
		}
		if strings.ContainsAny(err.Error(), "\x1b\n") {
			t.Errorf("%s: raw output in error %q", name, err)
		}
	}
}

// I3: the host skills store is not linked into bundle sandboxes.
func TestCreatePassesSkillsOff(t *testing.T) {
	fx := newFixture(t, "opencode", "1.18.33")
	p, err := BuildPlan(fx.m, fx.opts)
	if err != nil {
		t.Fatal(err)
	}
	_, create := step(p, "create")
	if v := flagValues(create, "--skills"); !slices.Equal(v, []string{"off"}) {
		t.Errorf("--skills %v in %v", v, create)
	}
}

// I3: a global anthropic sbx secret could be spent by the bundle through the
// base agent's api.anthropic.com access.
func TestGlobalAnthropicSecret(t *testing.T) {
	for _, agent := range []string{"claude-code", "opencode"} {
		version := map[string]string{"claude-code": "2.1.292", "opencode": "1.18.33"}[agent]
		fx := newFixture(t, agent, version)
		fx.opts.GlobalSecretsChecked = true
		fx.opts.GlobalSecrets = []string{"github", "anthropic"}
		_, err := Describe(fx.m, fx.opts)
		if err == nil || !strings.Contains(err.Error(), "--allow-global-anthropic-secret") {
			t.Errorf("%s: err %v", agent, err)
		}
		fx.opts.AllowGlobalAnthropicSecret = true
		info, err := Describe(fx.m, fx.opts)
		if err != nil {
			t.Fatalf("%s: %v", agent, err)
		}
		w := strings.Join(info.Warnings, "\n")
		if !strings.Contains(w, "anthropic") || !strings.Contains(w, "github") {
			t.Errorf("%s: warnings %q", agent, w)
		}
	}
	// Unchecked (sbx secret ls failed): refuse unless allowed.
	fx := newFixture(t, "claude-code", "2.1.292")
	fx.opts.GlobalSecretsChecked = false
	if _, err := Describe(fx.m, fx.opts); err == nil || !strings.Contains(err.Error(), "--allow-global-anthropic-secret") {
		t.Errorf("unchecked: err %v", err)
	}
	// None stored: no refusal, no anthropic warning.
	fx.opts.GlobalSecretsChecked = true
	fx.opts.GlobalSecrets = nil
	info, err := Describe(fx.m, fx.opts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(info.Warnings, "\n"), "global") {
		t.Errorf("warnings %v", info.Warnings)
	}
}

func TestParseGlobalSecrets(t *testing.T) {
	got := ParseSecretList([]byte("anthropic\n  github \n\nmcp:x:y\n"))
	if !slices.Equal(got, []string{"anthropic", "github", "mcp:x:y"}) {
		t.Errorf("got %v", got)
	}
	if !hasAnthropic([]string{"Anthropic"}) || hasAnthropic([]string{"github", "mcp:anthropic:k"}) {
		t.Error("hasAnthropic")
	}
}

// I4: an MCP-only secret goes to the MCP server through the gateway only; it
// is not bound to the bundle's egress hosts.
func TestMCPOnlySecretNotBoundToEgress(t *testing.T) {
	fx := newFixture(t, "claude-code", "2.1.292")
	p, err := BuildPlan(fx.m, fx.opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range steps(p, "secret", "set-custom") {
		if slices.Contains(flagValues(a, "--env"), "GITHUB_TOKEN") {
			t.Errorf("MCP-only secret bound to egress: %v", a)
		}
	}
	routes := map[string]SecretRoute{}
	for _, r := range p.SecretRoutes {
		routes[r.Name] = r
	}
	if r := routes["GITHUB_TOKEN"]; !slices.Equal(r.Hosts, []string{"mcp.example.com"}) || !strings.Contains(r.Via, "MCP gateway") {
		t.Errorf("GITHUB_TOKEN route %+v", r)
	}
	if r := routes["API_TOKEN"]; !slices.Equal(r.Hosts, []string{"api.example.org", "api.github.com"}) {
		t.Errorf("API_TOKEN route %+v", r)
	}
	if r := routes["model key"]; !slices.Equal(r.Hosts, []string{"models.example.com"}) {
		t.Errorf("model key route %+v", r)
	}
}

// I1: sbx uses the manifest's single base-agent host table.
func TestBaseHostsFromManifest(t *testing.T) {
	for agent, version := range map[string]string{"claude-code": "2.1.292", "opencode": "1.18.33"} {
		fx := newFixture(t, agent, version)
		info, err := Describe(fx.m, fx.opts)
		if err != nil {
			t.Fatal(err)
		}
		hosts, broad := manifest.BaseAgentHosts(agent)
		if !slices.Equal(info.BaseAgentHosts, hosts) || info.BaseAgentBroad != broad {
			t.Errorf("%s: %v %t", agent, info.BaseAgentHosts, info.BaseAgentBroad)
		}
	}
}
