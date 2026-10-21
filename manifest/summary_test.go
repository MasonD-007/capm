package manifest

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestEnforcedSummary(t *testing.T) {
	m := validManifest()
	m.Permissions.Egress = []string{"b.example.com", "api.github.com", "b.example.com"}
	s := m.EnforcedSummary()
	if want := []string{"api.github.com", "b.example.com"}; !reflect.DeepEqual(s.Egress, want) {
		t.Fatalf("Egress = %v, want %v", s.Egress, want)
	}
	want := []MCPEntry{{Name: "gh", URL: "https://mcp.example.com/mcp", Host: "mcp.example.com", Secret: "GITHUB_TOKEN"}}
	if !reflect.DeepEqual(s.MCP, want) {
		t.Fatalf("MCP = %+v, want %+v", s.MCP, want)
	}
	for _, h := range s.Egress {
		if h == "mcp.example.com" {
			t.Fatal("MCP host leaked into Egress")
		}
	}
}

func TestRender(t *testing.T) {
	m := validManifest()
	m.Permissions.Egress = []string{"api.github.com"}
	out := m.EnforcedSummary().Render()

	if strings.Contains(out, "only these hosts") {
		t.Errorf("Network heading over-claims:\n%s", out)
	}
	if !strings.Contains(out, "Network (declared bundle egress, port 443; the base agent's hosts and your model endpoint are listed separately below)") {
		t.Errorf("Network heading wrong:\n%s", out)
	}
	netIdx := strings.Index(out, "Network")
	mcpIdx := strings.Index(out, "MCP servers (reached via the host MCP gateway, not sandbox egress)")
	if netIdx < 0 || mcpIdx < 0 || netIdx > mcpIdx {
		t.Fatalf("missing/misordered sections:\n%s", out)
	}
	network := out[netIdx:mcpIdx]
	if !strings.Contains(network, "api.github.com") {
		t.Errorf("Network section lacks api.github.com:\n%s", out)
	}
	if strings.Contains(network, "mcp.example.com") {
		t.Errorf("MCP host listed under Network:\n%s", out)
	}
	if !strings.Contains(out[mcpIdx:], "mcp.example.com") {
		t.Errorf("MCP host not under MCP heading:\n%s", out)
	}
	for _, want := range []string{
		"Files", "./workspace", "read-only", "Secrets", "GITHUB_TOKEN", "Base agent", "claude-code",
		"Context files (read by the agent; not verified): docs/readme.md",
		"Model endpoint: supplied by you (not part of the egress list)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("Render missing %q:\n%s", want, out)
		}
	}
	if !strings.HasSuffix(strings.TrimRight(out, "\n"), "Model endpoint: supplied by you (not part of the egress list)") {
		t.Errorf("model endpoint line is not last:\n%s", out)
	}
}

func TestRenderEmpty(t *testing.T) {
	out := (&Manifest{}).EnforcedSummary().Render()
	if strings.Count(out, "(none)") < 4 {
		t.Errorf("empty sections should say (none):\n%s", out)
	}
}

func TestSummaryJSONTags(t *testing.T) {
	b, err := json.Marshal(validManifest().EnforcedSummary())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"egress"`, `"mounts"`, `"secrets"`, `"mcp"`, `"base"`, `"model"`, `"context"`, `"host"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("json missing %s: %s", k, b)
		}
	}
}

func TestMCPEntryHostIsLowercaseHostname(t *testing.T) {
	m := validManifest()
	m.MCP[0].URL = "https://MCP.Example.com:443/mcp"
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	if h := m.EnforcedSummary().MCP[0].Host; h != "mcp.example.com" {
		t.Fatalf("Host = %q, want mcp.example.com", h)
	}
}

func TestRenderSanitizesUnvalidatedStrings(t *testing.T) {
	m := validManifest() // deliberately not validated after mutation
	m.Secrets[0].Description = "a\u202eb\x1b[2J\u0085c\u2028d"
	m.Permissions.Egress = []string{"x\u009b.example.com"}
	out := m.EnforcedSummary().Render()
	for _, bad := range []string{"\u202e", "\x1b", "\u0085", "\u2028", "\u009b"} {
		if strings.Contains(out, bad) {
			t.Errorf("Render printed %q:\n%q", bad, out)
		}
	}
}
