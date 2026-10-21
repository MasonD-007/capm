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
		{"secret lowercase", func(m *Manifest) { m.Secrets[0].Name = "token" }, "secrets"},
		{"context absolute", func(m *Manifest) { m.Context = []string{"/etc/passwd"} }, "context"},
		{"context dotdot", func(m *Manifest) { m.Context = []string{"a/../../b"} }, "context"},
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
