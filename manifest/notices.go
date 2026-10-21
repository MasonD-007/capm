package manifest

import "slices"

// Shared user-facing statements about what capm does and does not do. They
// live here so the CLI (Render, capm run) and the website (through the API
// summary's `notices`) print the same words; the website must not hand-copy
// them (frontend/lib/notices.test.ts checks that).

// EgressEnforcementNotice is the egress status line shown in every Network
// section. v1 cannot enforce exact-host egress: see docs/sbx-findings.md §2.
const EgressEnforcementNotice = "Egress enforcement: NOT enforced yet. " +
	"sbx's per-sandbox network rules can only widen its default policy, so the sandbox may reach hosts beyond these lists; " +
	"`capm run` requires --allow-unenforced-egress."

// BaseHostsNotice accompanies a known base-agent host list.
const BaseHostsNotice = "The base agent's own hosts, as documented for the sbx kit (not verified against a running sandbox). " +
	"The sandbox can reach them whatever the bundle declares."

// BroadBaseHostsNotice is shown for a base agent whose kit allows a broad,
// unenumerated host list.
const BroadBaseHostsNotice = "This base agent's sbx kit allows a broad multi-provider host list that capm does not enumerate; " +
	"treat its egress as effectively unrestricted."

// UnknownBaseHostsNotice is shown for a base agent capm has no table for.
const UnknownBaseHostsNotice = "capm does not know this base agent's own network hosts."

// ContextNotice is the prompt-injection caveat for context files.
const ContextNotice = "Context files are text the agent reads and can carry prompt-injection instructions; capm cannot check their content."

// Notice sections, matching the summary's sections.
const (
	NoticeNetwork   = "network"
	NoticeBaseAgent = "baseAgent"
	NoticeContext   = "context"
)

// Notice is one shared statement and the summary section it belongs to.
type Notice struct {
	Section string `json:"section"`
	Text    string `json:"text"`
}

// baseAgentHosts is the sbx default runtime's known egress for each base
// agent's kit, from docs/sbx-findings.md §3 (all :443). UNVERIFIED: read from
// the kit sources and docs, never observed in a running sandbox (V5).
var baseAgentHosts = map[string]struct {
	hosts []string
	broad bool
}{
	"claude-code": {hosts: []string{"api.anthropic.com", "platform.claude.com", "downloads.claude.ai",
		"claude.com", "mcp-proxy.anthropic.com", "bridge.claudeusercontent.com"}},
	// findings §3: "opencode adds a broad multi-provider list"; not enumerated.
	"opencode": {broad: true},
}

// BaseAgentHosts returns the hosts the sbx kit for agent allows on its own
// (a copy), and whether that list is broad and unenumerated. Unknown agents
// return nil, false. Unverified; see docs/sbx-findings.md.
func BaseAgentHosts(agent string) (hosts []string, broad bool) {
	e, ok := baseAgentHosts[agent]
	if !ok {
		return nil, false
	}
	return slices.Clone(e.hosts), e.broad
}

func notices(agent string) []Notice {
	n := []Notice{{NoticeNetwork, EgressEnforcementNotice}}
	switch hosts, broad := BaseAgentHosts(agent); {
	case broad:
		n = append(n, Notice{NoticeBaseAgent, BroadBaseHostsNotice})
	case len(hosts) > 0:
		n = append(n, Notice{NoticeBaseAgent, BaseHostsNotice})
	default:
		n = append(n, Notice{NoticeBaseAgent, UnknownBaseHostsNotice})
	}
	return append(n, Notice{NoticeContext, ContextNotice})
}

// NoticeTexts returns the texts of the summary's notices for one section.
func (s Summary) NoticeTexts(section string) []string {
	var out []string
	for _, n := range s.Notices {
		if n.Section == section {
			out = append(out, n.Text)
		}
	}
	return out
}
