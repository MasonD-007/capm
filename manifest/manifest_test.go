package manifest

import "testing"

const goodYAML = `apiVersion: capm/v0
kind: Agent
metadata:
  name: pr-reviewer
  version: 0.1.0
  description: Reviews PRs.
  authors: [MasonD-007]
base:
  agent: claude-code
  version: 1.0.0
interface:
  type: tty
model:
  api: openai-compatible
  requires:
    toolCalling: true
    minContextTokens: 32000
permissions:
  egress:
    - api.github.com
  mounts:
    - path: ./workspace
      mode: read-only
secrets:
  - name: GITHUB_TOKEN
    description: Token
mcp:
  - name: gh
    url: https://mcp.example.com/mcp
    secret: GITHUB_TOKEN
context:
  - docs/readme.md
`

func TestParse(t *testing.T) {
	m, err := Parse([]byte(goodYAML))
	if err != nil {
		t.Fatal(err)
	}
	if m.Metadata.Name != "pr-reviewer" || m.Base.Agent != "claude-code" ||
		!m.Model.Requires.ToolCalling || m.Model.Requires.MinContextTokens != 32000 ||
		m.Permissions.Mounts[0].Mode != "read-only" || m.MCP[0].Secret != "GITHUB_TOKEN" {
		t.Fatalf("unexpected parse result: %+v", m)
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("parsed manifest should validate: %v", err)
	}
}

func TestParseRejectsUnknownField(t *testing.T) {
	if _, err := Parse([]byte(goodYAML + "bogus: 1\n")); err == nil {
		t.Fatal("expected error for unknown top-level field")
	}
	if _, err := Parse([]byte("runtime:\n  image: x\n")); err == nil {
		t.Fatal("expected error for runtime field")
	}
}

func TestParseRejectsInvalidYAML(t *testing.T) {
	if _, err := Parse([]byte("a: [")); err == nil {
		t.Fatal("expected error")
	}
}
