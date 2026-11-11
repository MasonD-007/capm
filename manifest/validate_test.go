package manifest

import (
	"strings"
	"testing"
)

func validManifest() *Manifest {
	return &Manifest{
		APIVersion: "capm/v0",
		Kind:       "Agent",
		Metadata: Metadata{
			Name:        "pr-reviewer",
			Version:     "0.1.0",
			Description: "Reviews open pull requests and leaves comments.",
			Authors:     []string{"MasonD-007"},
		},
		Base:      Base{Agent: "claude-code", Version: "1.0.0"},
		Interface: Interface{Type: "tty"},
		Model: Model{API: "openai-compatible", Requires: ModelRequires{
			ToolCalling: true, MinContextTokens: 32000,
		}},
		Permissions: Permissions{
			Egress: []string{"api.github.com"},
			Mounts: []Mount{{Path: "./workspace", Mode: "read-only"}},
		},
		Secrets: []Secret{{Name: "GITHUB_TOKEN", Description: "Token"}},
		MCP:     []MCP{{Name: "gh", URL: "https://mcp.example.com/mcp", Secret: "GITHUB_TOKEN"}},
		Context: []string{"docs/readme.md"},
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(m *Manifest)
		wantErr string // empty means valid
	}{
		{"valid", func(m *Manifest) {}, ""},
		{"bad apiVersion", func(m *Manifest) { m.APIVersion = "capm/v1" }, "apiVersion"},
		{"empty apiVersion", func(m *Manifest) { m.APIVersion = "" }, "apiVersion"},
		{"bad kind", func(m *Manifest) { m.Kind = "Tool" }, "kind"},
		{"empty kind", func(m *Manifest) { m.Kind = "" }, "kind"},
		{"bad name uppercase", func(m *Manifest) { m.Metadata.Name = "Bad" }, "metadata.name"},
		{"bad name leading dash", func(m *Manifest) { m.Metadata.Name = "-bad" }, "metadata.name"},
		{"bad name too long", func(m *Manifest) { m.Metadata.Name = "a" + strings.Repeat("b", 64) }, "metadata.name"},
		{"bad version", func(m *Manifest) { m.Metadata.Version = "1.0" }, "metadata.version"},
		{"semver prerelease ok", func(m *Manifest) { m.Metadata.Version = "1.0.0-rc.1+build.5" }, ""},
		{"unknown agent", func(m *Manifest) { m.Base.Agent = "emacs" }, "base.agent"},
		{"opencode ok", func(m *Manifest) { m.Base.Agent = "opencode" }, ""},
		{"interface http", func(m *Manifest) { m.Interface.Type = "http" }, "interface.type"},
		{"egress uppercase", func(m *Manifest) { m.Permissions.Egress = []string{"API.github.com"} }, "egress"},
		{"egress port", func(m *Manifest) { m.Permissions.Egress = []string{"github.com:8080"} }, "egress"},
		{"egress wildcard", func(m *Manifest) { m.Permissions.Egress = []string{"*.github.com"} }, "egress"},
		{"egress ip", func(m *Manifest) { m.Permissions.Egress = []string{"1.2.3.4"} }, "egress"},
		{"egress trailing dot", func(m *Manifest) { m.Permissions.Egress = []string{"github.com."} }, "egress"},
		{"egress path", func(m *Manifest) { m.Permissions.Egress = []string{"github.com/x"} }, "egress"},
		{"egress empty", func(m *Manifest) { m.Permissions.Egress = []string{""} }, "egress"},
		{"mount dotdot", func(m *Manifest) { m.Permissions.Mounts[0].Path = "../etc" }, "mounts"},
		{"mount absolute", func(m *Manifest) { m.Permissions.Mounts[0].Path = "/etc" }, "mounts"},
		{"mount sneaky", func(m *Manifest) { m.Permissions.Mounts[0].Path = "a/../../b" }, "mounts"},
		{"mount bad mode", func(m *Manifest) { m.Permissions.Mounts[0].Mode = "rw" }, "mode"},
		{"mount read-write ok", func(m *Manifest) { m.Permissions.Mounts[0].Mode = "read-write" }, ""},
		{"mcp http", func(m *Manifest) { m.MCP[0].URL = "http://x.com/mcp" }, "mcp"},
		{"ctl newline in secret description", func(m *Manifest) { m.Secrets[0].Description = "a\nSecrets: none" }, "control characters"},
		{"ctl ESC in mount path", func(m *Manifest) { m.Permissions.Mounts[0].Path = "./w\x1b[2J" }, "control characters"},
		{"ctl in description", func(m *Manifest) { m.Metadata.Description = "x\ry" }, "control characters"},
		{"ctl DEL in context", func(m *Manifest) { m.Context = []string{"a\x7f"} }, "control characters"},
		{"base version empty", func(m *Manifest) { m.Base.Version = "" }, "base.version"},
		{"base version space", func(m *Manifest) { m.Base.Version = "1 .0" }, "base.version"},
		{"mcp userinfo", func(m *Manifest) { m.MCP[0].URL = "https://user:pw@mcp.example.com/mcp" }, "userinfo"},
		{"mcp undeclared secret", func(m *Manifest) { m.MCP[0].Secret = "NOPE" }, "mcp"},
		{"mcp no secret ok", func(m *Manifest) { m.MCP[0].Secret = "" }, ""},
		{"mcp name comma", func(m *Manifest) { m.MCP[0].Name = "x,notion" }, "mcp[0].name"},
		{"mcp name colon", func(m *Manifest) { m.MCP[0].Name = "a:b" }, "mcp[0].name"},
		{"mcp name upper", func(m *Manifest) { m.MCP[0].Name = "GH" }, "mcp[0].name"},
		{"mcp name empty", func(m *Manifest) { m.MCP[0].Name = "" }, "mcp[0].name"},
		{"mcp name leading dash", func(m *Manifest) { m.MCP[0].Name = "-gh" }, "mcp[0].name"},
		{"mcp name too long", func(m *Manifest) { m.MCP[0].Name = strings.Repeat("a", 65) }, "mcp[0].name"},
		{"mcp name 64 ok", func(m *Manifest) { m.MCP[0].Name = strings.Repeat("a", 64) }, ""},
		{"mcp name duplicate", func(m *Manifest) { m.MCP = append(m.MCP, m.MCP[0]) }, "duplicate"},
		{"secret lowercase", func(m *Manifest) { m.Secrets[0].Name = "token" }, "secrets"},
		{"context absolute", func(m *Manifest) { m.Context = []string{"/etc/passwd"} }, "context"},
		{"context dotdot", func(m *Manifest) { m.Context = []string{"a/../../b"} }, "context"},
		{"context leading dotdot", func(m *Manifest) { m.Context = []string{"../x"} }, "context"},
		{"context not clean inner dotdot", func(m *Manifest) { m.Context = []string{"x/../y"} }, "context"},
		{"context not clean dot prefix", func(m *Manifest) { m.Context = []string{"./docs/readme.md"} }, "context"},
		{"context not clean double slash", func(m *Manifest) { m.Context = []string{"docs//readme.md"} }, "context"},
		{"context kit expression", func(m *Manifest) { m.Context = []string{"a${{x}}.md"} }, "context"},
		{"context comment close", func(m *Manifest) { m.Context = []string{"a-->b.md"} }, "context"},
		// I2: Unicode controls beyond C0/DEL.
		{"ctl C1 NEL", func(m *Manifest) { m.Metadata.Description = "a\u0085b" }, "control characters"},
		{"ctl C1 CSI", func(m *Manifest) { m.Secrets[0].Description = "a\u009b2Jb" }, "control characters"},
		{"ctl line separator", func(m *Manifest) { m.Metadata.Description = "a\u2028b" }, "control characters"},
		{"ctl paragraph separator", func(m *Manifest) { m.Metadata.Description = "a\u2029b" }, "control characters"},
		{"ctl bidi RLO", func(m *Manifest) { m.Metadata.Description = "a\u202eb" }, "control characters"},
		{"ctl bidi LRE", func(m *Manifest) { m.Metadata.Description = "a\u202ab" }, "control characters"},
		{"ctl bidi isolate", func(m *Manifest) { m.Secrets[0].Description = "a\u2066b" }, "control characters"},
		{"ctl bidi PDI", func(m *Manifest) { m.Metadata.Authors = []string{"a\u2069"} }, "control characters"},
		{"ctl LRM", func(m *Manifest) { m.Metadata.Description = "a\u200eb" }, "control characters"},
		{"ctl RLM", func(m *Manifest) { m.Metadata.Description = "a\u200fb" }, "control characters"},
		{"ctl ALM", func(m *Manifest) { m.Metadata.Description = "a\u061cb" }, "control characters"},
		{"unicode text ok", func(m *Manifest) { m.Metadata.Description = "Prüft Pull-Requests ✓ 日本語" }, ""},
		// I5: MCP hosts validated like egress hosts.
		{"mcp host ipv4", func(m *Manifest) { m.MCP[0].URL = "https://10.0.0.1/mcp" }, "mcp[0].url"},
		{"mcp host ipv6", func(m *Manifest) { m.MCP[0].URL = "https://[::1]/mcp" }, "mcp[0].url"},
		{"mcp host localhost", func(m *Manifest) { m.MCP[0].URL = "https://localhost/mcp" }, "mcp[0].url"},
		{"mcp host localhost subdomain", func(m *Manifest) { m.MCP[0].URL = "https://a.localhost/mcp" }, "mcp[0].url"},
		{"mcp host .local", func(m *Manifest) { m.MCP[0].URL = "https://printer.local/mcp" }, "mcp[0].url"},
		{"mcp host .internal", func(m *Manifest) { m.MCP[0].URL = "https://metadata.google.internal/mcp" }, "mcp[0].url"},
		{"mcp host port", func(m *Manifest) { m.MCP[0].URL = "https://mcp.example.com:8443/mcp" }, "mcp[0].url"},
		{"mcp host port 443 ok", func(m *Manifest) { m.MCP[0].URL = "https://mcp.example.com:443/mcp" }, ""},
		{"mcp host empty port", func(m *Manifest) { m.MCP[0].URL = "https://mcp.example.com:/mcp" }, "mcp[0].url"},
		{"mcp host underscore", func(m *Manifest) { m.MCP[0].URL = "https://mcp_x.example.com/mcp" }, "mcp[0].url"},
		{"mcp host trailing dot", func(m *Manifest) { m.MCP[0].URL = "https://mcp.example.com./mcp" }, "mcp[0].url"},
		{"mcp host uppercase ok", func(m *Manifest) { m.MCP[0].URL = "https://MCP.Example.com/mcp" }, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := validManifest()
			tt.mutate(m)
			err := m.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateReturnsAllProblems(t *testing.T) {
	m := validManifest()
	m.Metadata.Name = "Bad"
	m.Base.Agent = "emacs"
	err := m.Validate()
	if err == nil || !strings.Contains(err.Error(), "metadata.name") || !strings.Contains(err.Error(), "base.agent") {
		t.Fatalf("expected both problems, got %v", err)
	}
}
