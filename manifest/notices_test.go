package manifest

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestBaseAgentHosts(t *testing.T) {
	hosts, broad := BaseAgentHosts("claude-code")
	if broad || !slices.Contains(hosts, "api.anthropic.com") || !slices.Contains(hosts, "mcp-proxy.anthropic.com") {
		t.Errorf("claude-code: %v broad=%t", hosts, broad)
	}
	hosts[0] = "mutated.example" // callers get a copy
	if h, _ := BaseAgentHosts("claude-code"); h[0] == "mutated.example" {
		t.Error("BaseAgentHosts returned the shared table")
	}
	if hosts, broad := BaseAgentHosts("opencode"); !broad || len(hosts) != 0 {
		t.Errorf("opencode: %v broad=%t", hosts, broad)
	}
	if hosts, broad := BaseAgentHosts("emacs"); hosts != nil || broad {
		t.Errorf("unknown agent: %v %t", hosts, broad)
	}
}

func TestSummaryNoticesAndBaseHosts(t *testing.T) {
	s := validManifest().EnforcedSummary()
	if !slices.Contains(s.BaseHosts, "api.anthropic.com") || s.BaseHostsBroad {
		t.Errorf("claude-code base hosts %v broad %t", s.BaseHosts, s.BaseHostsBroad)
	}
	if got := s.NoticeTexts(NoticeNetwork); !slices.Equal(got, []string{EgressEnforcementNotice}) {
		t.Errorf("network notices %v", got)
	}
	if len(s.NoticeTexts(NoticeContext)) != 1 || len(s.NoticeTexts(NoticeBaseAgent)) != 1 {
		t.Errorf("notices %+v", s.Notices)
	}

	m := validManifest()
	m.Base.Agent = "opencode"
	s = m.EnforcedSummary()
	if !s.BaseHostsBroad || len(s.BaseHosts) != 0 {
		t.Errorf("opencode base hosts %v broad %t", s.BaseHosts, s.BaseHostsBroad)
	}
	if got := strings.Join(s.NoticeTexts(NoticeBaseAgent), " "); !strings.Contains(got, "effectively unrestricted") {
		t.Errorf("opencode base notice %q", got)
	}

	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{`"notices"`, `"baseHosts"`, `"baseHostsBroad"`, `"section"`, `"text"`, `"network"`} {
		if !strings.Contains(string(b), k) {
			t.Errorf("json lacks %s: %s", k, b)
		}
	}
}

func TestRenderEnforcementAndBaseHosts(t *testing.T) {
	out := validManifest().EnforcedSummary().Render()
	net := out[strings.Index(out, "Network"):strings.Index(out, "Files")]
	if !strings.Contains(net, EgressEnforcementNotice) {
		t.Errorf("Network section lacks the enforcement notice:\n%s", out)
	}
	base := out[strings.Index(out, "Base agent"):]
	for _, h := range []string{"api.anthropic.com", "platform.claude.com", "bridge.claudeusercontent.com"} {
		if !strings.Contains(base, h) {
			t.Errorf("Base agent section lacks %s:\n%s", h, out)
		}
	}
	if strings.Contains(out, "not listed here") {
		t.Errorf("Render still hides base-agent hosts:\n%s", out)
	}

	m := validManifest()
	m.Base.Agent = "opencode"
	if out := m.EnforcedSummary().Render(); !strings.Contains(out, "effectively unrestricted") {
		t.Errorf("opencode render lacks broad-egress warning:\n%s", out)
	}
}

// User-facing text must not present the declared summary as enforced or
// guaranteed (spec anti-goal). The only allowed use of "enforced" is the
// negative status line.
func TestRenderNeverClaimsEnforcement(t *testing.T) {
	for _, agent := range []string{"claude-code", "opencode"} {
		m := validManifest()
		m.Base.Agent = agent
		s := m.EnforcedSummary()
		out := strings.ToLower(s.Render())
		for _, n := range s.Notices {
			out = strings.ReplaceAll(out, strings.ToLower(n.Text), "")
		}
		for _, bad := range []string{"enforced", "guarantee"} {
			if strings.Contains(out, bad) {
				t.Errorf("%s: render says %q outside the enforcement notice:\n%s", agent, bad, s.Render())
			}
		}
	}
	if !strings.Contains(EgressEnforcementNotice, "NOT enforced") {
		t.Errorf("notice must say NOT enforced: %q", EgressEnforcementNotice)
	}
}
