package manifest

import (
	"fmt"
	"net/url"
	"slices"
	"strings"
)

// Summary is the user-facing statement of what a bundle is allowed to do. It
// is embedded in the backend API, hence the json tags.
type Summary struct {
	// Egress is the sandbox egress allowlist: sorted, de-duplicated. MCP hosts
	// are deliberately absent; they are reached through the host MCP gateway.
	Egress  []string   `json:"egress"`
	Mounts  []Mount    `json:"mounts"`
	Secrets []Secret   `json:"secrets"`
	MCP     []MCPEntry `json:"mcp"`
	Base    Base       `json:"base"`
	Model   Model      `json:"model"`
	// Context lists files the agent reads. Their content is not verified.
	Context []string `json:"context"`
}

// MCPEntry is one MCP server; Host is parsed from URL.
type MCPEntry struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Host   string `json:"host"`
	Secret string `json:"secret,omitempty"`
}

// EnforcedSummary derives the summary from the manifest. Slices are never nil
// so the JSON form has [] rather than null.
func (m *Manifest) EnforcedSummary() Summary {
	egress := slices.Clone(m.Permissions.Egress)
	slices.Sort(egress)
	egress = slices.Compact(egress)

	mcp := make([]MCPEntry, 0, len(m.MCP))
	for _, c := range m.MCP {
		host := ""
		if u, err := url.Parse(c.URL); err == nil {
			host = u.Host
		}
		mcp = append(mcp, MCPEntry{Name: c.Name, URL: c.URL, Host: host, Secret: c.Secret})
	}
	return Summary{
		Egress:  nonNil(egress),
		Mounts:  nonNil(slices.Clone(m.Permissions.Mounts)),
		Secrets: nonNil(slices.Clone(m.Secrets)),
		MCP:     mcp,
		Base:    m.Base,
		Model:   m.Model,
		Context: nonNil(slices.Clone(m.Context)),
	}
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// Render formats the summary as plain text.
func (s Summary) Render() string {
	var b strings.Builder
	section := func(title string, n int, line func(i int) string) {
		fmt.Fprintf(&b, "%s\n", title)
		if n == 0 {
			b.WriteString("  (none)\n")
		}
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "  %s\n", line(i))
		}
		b.WriteString("\n")
	}
	section("Network (sandbox may reach only these hosts, port 443)", len(s.Egress),
		func(i int) string { return s.Egress[i] })
	section("Files (mounted from your machine)", len(s.Mounts),
		func(i int) string { return fmt.Sprintf("%s (%s)", s.Mounts[i].Path, s.Mounts[i].Mode) })
	section("Secrets (you will be asked to provide these)", len(s.Secrets), func(i int) string {
		if d := s.Secrets[i].Description; d != "" {
			return fmt.Sprintf("%s: %s", s.Secrets[i].Name, d)
		}
		return s.Secrets[i].Name
	})
	section("MCP servers (reached via the host MCP gateway, not sandbox egress)", len(s.MCP), func(i int) string {
		c := s.MCP[i]
		line := fmt.Sprintf("%s: %s (host %s)", c.Name, c.URL, c.Host)
		if c.Secret != "" {
			line += " using secret " + c.Secret
		}
		return line
	})

	b.WriteString("Base agent\n")
	base := "  " + s.Base.Agent
	if s.Base.Version != "" {
		base += " " + s.Base.Version
	}
	// sbx's own hosts for the base agent are not listed: the sbx findings are
	// unverified and version dependent, so we do not state them here.
	b.WriteString(base + "\n  (the base agent's own network hosts are set by sbx and not listed here)\n\n")

	if len(s.Context) == 0 {
		b.WriteString("Context files (read by the agent; not verified): (none)\n")
	} else {
		fmt.Fprintf(&b, "Context files (read by the agent; not verified): %s\n", strings.Join(s.Context, ", "))
	}
	b.WriteString("Model endpoint: supplied by you (not part of the egress list)\n")
	return b.String()
}
