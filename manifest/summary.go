package manifest

import (
	"fmt"
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
	// BaseHosts is the base agent kit's own egress (BaseAgentHosts); empty
	// with BaseHostsBroad set when that list is broad and not enumerated.
	BaseHosts      []string `json:"baseHosts"`
	BaseHostsBroad bool     `json:"baseHostsBroad"`
	// Notices are the shared caveats (see notices.go), keyed by section.
	Notices []Notice `json:"notices"`
}

// MCPEntry is one MCP server; Host is parsed from URL.
type MCPEntry struct {
	Name   string `json:"name"`
	URL    string `json:"url"`
	Host   string `json:"host"`
	Secret string `json:"secret,omitempty"`
}

// EnforcedSummary derives the summary from the manifest. The name is
// historical: it is what the manifest declares plus what capm knows about the
// base agent, NOT what is enforced (see EgressEnforcementNotice). Slices are
// never nil so the JSON form has [] rather than null.
func (m *Manifest) EnforcedSummary() Summary {
	egress := slices.Clone(m.Permissions.Egress)
	slices.Sort(egress)
	egress = slices.Compact(egress)

	mcp := make([]MCPEntry, 0, len(m.MCP))
	for _, c := range m.MCP {
		host, _ := MCPHost(c.URL) // "" for a URL Validate would reject
		mcp = append(mcp, MCPEntry{Name: c.Name, URL: c.URL, Host: host, Secret: c.Secret})
	}
	baseHosts, broad := BaseAgentHosts(m.Base.Agent)
	return Summary{
		BaseHosts:      nonNil(baseHosts),
		BaseHostsBroad: broad,
		Notices:        notices(m.Base.Agent),
		Egress:         nonNil(egress),
		Mounts:         nonNil(slices.Clone(m.Permissions.Mounts)),
		Secrets:        nonNil(slices.Clone(m.Secrets)),
		MCP:            mcp,
		Base:           m.Base,
		Model:          m.Model,
		Context:        nonNil(slices.Clone(m.Context)),
	}
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// Render formats the summary as plain text. Every manifest-supplied string
// goes through DisplaySafe, so a manifest that skipped Validate still cannot
// write terminal control sequences.
func (s Summary) Render() string {
	var b strings.Builder
	d := DisplaySafe
	section := func(title string, notes []string, n int, line func(i int) string) {
		fmt.Fprintf(&b, "%s\n", title)
		for _, t := range notes {
			fmt.Fprintf(&b, "  ! %s\n", t)
		}
		if n == 0 {
			b.WriteString("  (none)\n")
		}
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "  %s\n", line(i))
		}
		b.WriteString("\n")
	}
	section("Network (declared bundle egress, port 443; the base agent's hosts and your model endpoint are listed separately below)",
		s.NoticeTexts(NoticeNetwork), len(s.Egress),
		func(i int) string { return d(s.Egress[i]) })
	section("Files (mounted from your machine)", nil, len(s.Mounts),
		func(i int) string { return fmt.Sprintf("%s (%s)", d(s.Mounts[i].Path), d(s.Mounts[i].Mode)) })
	section("Secrets (you will be asked to provide these)", nil, len(s.Secrets), func(i int) string {
		if desc := s.Secrets[i].Description; desc != "" {
			return fmt.Sprintf("%s: %s", d(s.Secrets[i].Name), d(desc))
		}
		return d(s.Secrets[i].Name)
	})
	section("MCP servers (reached via the host MCP gateway, not sandbox egress)", nil, len(s.MCP), func(i int) string {
		c := s.MCP[i]
		line := fmt.Sprintf("%s: %s (host %s)", d(c.Name), d(c.URL), d(c.Host))
		if c.Secret != "" {
			line += " using secret " + d(c.Secret)
		}
		return line
	})

	base := d(s.Base.Agent)
	if s.Base.Version != "" {
		base += " " + d(s.Base.Version)
	}
	section("Base agent: "+base+" (its own sbx egress, in addition to the bundle's)",
		s.NoticeTexts(NoticeBaseAgent), max(len(s.BaseHosts), b2i(s.BaseHostsBroad)),
		func(i int) string {
			if len(s.BaseHosts) == 0 {
				return "(a broad list, not enumerated by capm)"
			}
			return s.BaseHosts[i]
		})

	if len(s.Context) == 0 {
		b.WriteString("Context files (read by the agent; not verified): (none)\n")
	} else {
		ctx := make([]string, len(s.Context))
		for i, c := range s.Context {
			ctx[i] = d(c)
		}
		fmt.Fprintf(&b, "Context files (read by the agent; not verified): %s\n", strings.Join(ctx, ", "))
		for _, t := range s.NoticeTexts(NoticeContext) {
			fmt.Fprintf(&b, "  ! %s\n", t)
		}
	}
	b.WriteString("Model endpoint: supplied by you (not part of the egress list)\n")
	return b.String()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
