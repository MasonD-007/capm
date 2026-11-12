package manifest

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// bare returns a valid manifest with no declared exposure at all.
func bare() *Manifest {
	m := validManifest()
	m.Permissions = Permissions{Egress: []string{"api.example.com"}}
	m.Secrets, m.MCP, m.Context = nil, nil, nil
	return m
}

func hosts(n int) []string {
	var h []string
	for i := 0; i < n; i++ {
		h = append(h, fmt.Sprintf("h%02d.example.com", i))
	}
	return h
}

func ids(ls []RiskLabel) []string {
	out := []string{}
	for _, l := range ls {
		out = append(out, l.ID)
	}
	return out
}

func find(ls []RiskLabel, id string) (RiskLabel, bool) {
	for _, l := range ls {
		if l.ID == id {
			return l, true
		}
	}
	return RiskLabel{}, false
}

func TestRiskLabelsNoneIsNonNilEmpty(t *testing.T) {
	ls := bare().RiskLabels()
	if ls == nil || len(ls) != 0 {
		t.Fatalf("want non-nil empty, got %#v", ls)
	}
	if HighestSeverity(ls) != "" || HighestSeverity(nil) != "" {
		t.Error("HighestSeverity of none must be empty")
	}
}

func TestRiskRules(t *testing.T) {
	secretNoMCP := func(egress int) *Manifest {
		m := bare()
		m.Permissions.Egress = hosts(egress)
		m.Secrets = []Secret{{Name: "TOKEN"}}
		return m
	}
	withMounts := func(ms ...Mount) *Manifest {
		m := bare()
		m.Permissions.Mounts = ms
		return m
	}
	tests := []struct {
		name     string
		m        *Manifest
		id       string
		want     bool
		severity string
		reason   string
	}{
		{"rw mount", withMounts(Mount{"./workspace", "read-write"}),
			"mount_read_write", true, "high", "Mounts read-write (1): ./workspace"},
		{"rw mounts sorted", withMounts(Mount{"./b", "read-write"}, Mount{"./a", "read-write"}, Mount{"./c", "read-only"}),
			"mount_read_write", true, "high", "Mounts read-write (2): ./a, ./b"},
		{"ro mount is not rw", withMounts(Mount{"./workspace", "read-only"}),
			"mount_read_write", false, "", ""},
		{"root mount .", withMounts(Mount{".", "read-only"}),
			"mount_workspace_root", true, "high", "Mounts the workspace root (1): . (read-only)"},
		{"root mount via a/..", withMounts(Mount{"a/..", "read-write"}),
			"mount_workspace_root", true, "high", "Mounts the workspace root (1): a/.. (read-write)"},
		{"root mount ./", withMounts(Mount{"./", "read-only"}),
			"mount_workspace_root", true, "high", "Mounts the workspace root (1): ./ (read-only)"},
		{"subdir is not root", withMounts(Mount{"./workspace", "read-only"}, Mount{".hidden", "read-only"}, Mount{"..x", "read-only"}),
			"mount_workspace_root", false, "", ""},
		{"10 hosts", func() *Manifest { m := bare(); m.Permissions.Egress = hosts(10); return m }(), "egress_many_hosts", false, "", ""},
		{"11 hosts", func() *Manifest { m := bare(); m.Permissions.Egress = hosts(11); return m }(), "egress_many_hosts", true, "high", "Declares 11 egress hosts (more than 10)"},
		{"11 entries but 10 distinct", func() *Manifest {
			m := bare()
			m.Permissions.Egress = append(hosts(10), "h00.example.com")
			return m
		}(), "egress_many_hosts", false, "", ""},
		{"secret + 3 hosts", secretNoMCP(3), "secret_many_hosts", false, "", ""},
		{"secret + 4 hosts", secretNoMCP(4), "secret_many_hosts", true, "high", "Secrets offered to every egress host (1 secret, 4 hosts): TOKEN"},
		{"secret + 4 entries, 3 distinct", func() *Manifest {
			m := secretNoMCP(3)
			m.Permissions.Egress = append(m.Permissions.Egress, "H00.example.com", "h00.example.com")
			return m
		}(), "secret_many_hosts", false, "", ""},
		{"mcp-bound secret never goes to egress hosts", func() *Manifest {
			m := secretNoMCP(11)
			m.MCP = []MCP{{Name: "gh", URL: "https://mcp.example.com/mcp", Secret: "TOKEN"}}
			return m
		}(), "secret_many_hosts", false, "", ""},
		{"only the unbound secret is listed", func() *Manifest {
			m := secretNoMCP(4)
			m.Secrets = []Secret{{Name: "ZED"}, {Name: "BOUND"}, {Name: "ALPHA"}}
			m.MCP = []MCP{{Name: "gh", URL: "https://mcp.example.com/mcp", Secret: "BOUND"}}
			return m
		}(), "secret_many_hosts", true, "high", "Secrets offered to every egress host (2 secrets, 4 hosts): ALPHA, ZED"},
		{"no secrets, many hosts", func() *Manifest { m := bare(); m.Permissions.Egress = hosts(5); return m }(), "secret_many_hosts", false, "", ""},
		{"secrets declared", func() *Manifest {
			m := bare()
			m.Secrets = []Secret{{Name: "B"}, {Name: "A"}}
			return m
		}(), "secrets_declared", true, "caution", "Declares secrets (2): A, B"},
		{"no secrets", bare(), "secrets_declared", false, "", ""},
		{"mcp", func() *Manifest {
			m := bare()
			m.MCP = []MCP{{Name: "zz", URL: "https://z.example.com/x"}, {Name: "aa", URL: "https://a.example.com/x"}}
			return m
		}(), "mcp_servers", true, "caution", "Uses MCP servers (2): aa (a.example.com), zz (z.example.com)"},
		{"no mcp", bare(), "mcp_servers", false, "", ""},
		{"opencode broad", func() *Manifest { m := bare(); m.Base.Agent = "opencode"; return m }(),
			"base_egress_broad", true, "caution", "Base agent opencode allows a broad host list that capm does not enumerate"},
		{"claude-code enumerated", bare(), "base_egress_broad", false, "", ""},
		{"context", func() *Manifest { m := bare(); m.Context = []string{"b.md", "a.md"}; return m }(),
			"context_files", true, "caution", "Reads context files (2): a.md, b.md"},
		{"no context", bare(), "context_files", false, "", ""},
		{"no egress", func() *Manifest { m := bare(); m.Permissions.Egress = nil; return m }(),
			"egress_none", true, "info", "Declares egress hosts (0)"},
		{"one egress", bare(), "egress_none", false, "", ""},
		{"ro only", withMounts(Mount{"./b", "read-only"}, Mount{"./a", "read-only"}),
			"mounts_read_only", true, "info", "Mounts are all read-only (2): ./a, ./b"},
		{"ro and rw", withMounts(Mount{"./a", "read-only"}, Mount{"./b", "read-write"}),
			"mounts_read_only", false, "", ""},
		{"no mounts", bare(), "mounts_read_only", false, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l, ok := find(tc.m.RiskLabels(), tc.id)
			if ok != tc.want {
				t.Fatalf("%s present = %v, want %v (labels %v)", tc.id, ok, tc.want, ids(tc.m.RiskLabels()))
			}
			if !ok {
				return
			}
			if l.Severity != tc.severity || l.Reason != tc.reason {
				t.Errorf("got %+v, want severity %q reason %q", l, tc.severity, tc.reason)
			}
		})
	}
}

func TestRiskLabelsOrderAndWording(t *testing.T) {
	m := validManifest()
	m.Base.Agent = "opencode"
	m.Permissions.Egress = hosts(12)
	m.Permissions.Mounts = []Mount{{".", "read-write"}, {"./a", "read-only"}}
	m.Secrets = []Secret{{Name: "X"}, {Name: "GITHUB_TOKEN"}}
	ls := m.RiskLabels()
	want := []string{"egress_many_hosts", "mount_read_write", "mount_workspace_root", "secret_many_hosts",
		"base_egress_broad", "context_files", "mcp_servers", "secrets_declared"}
	if !reflect.DeepEqual(ids(ls), want) {
		t.Fatalf("order = %v, want %v", ids(ls), want)
	}
	if HighestSeverity(ls) != "high" {
		t.Error("highest must be high")
	}
	if HighestSeverity([]RiskLabel{{Severity: "info"}, {Severity: "caution"}}) != "caution" ||
		HighestSeverity([]RiskLabel{{Severity: "info"}}) != "info" {
		t.Error("HighestSeverity wrong")
	}
	for _, l := range ls {
		for _, w := range []string{"safe", "unsafe", "dangerous", "malicious", "trusted"} {
			if strings.Contains(strings.ToLower(l.Reason), w) {
				t.Errorf("%s reason uses %q: %s", l.ID, w, l.Reason)
			}
		}
	}
}

// Rules only cover inputs that can pass Validate: wildcard hosts and absolute
// or ".." mounts are rejected, so there is no rule for them; "." and "a/.."
// do pass and are the workspace root.
func TestRiskInputsAreReachable(t *testing.T) {
	for _, p := range []string{".", "./", "a/.."} {
		m := bare()
		m.Permissions.Mounts = []Mount{{p, "read-only"}}
		if err := m.Validate(); err != nil {
			t.Errorf("mount %q should validate: %v", p, err)
		}
	}
	for _, p := range []string{"..", "../x", "/", "/etc"} {
		m := bare()
		m.Permissions.Mounts = []Mount{{p, "read-only"}}
		if m.Validate() == nil {
			t.Errorf("mount %q must not validate (no parent-path rule needed)", p)
		}
	}
	m := bare()
	m.Permissions.Egress = []string{"*.example.com"}
	if m.Validate() == nil {
		t.Error("wildcard egress must not validate (no wildcard rule needed)")
	}
}

func TestRiskLabelsOrderIndependent(t *testing.T) {
	h := hosts(5)
	a := validManifest()
	a.Permissions.Egress = h
	a.Permissions.Mounts = []Mount{{"./a", "read-write"}, {"./b", "read-write"}, {".", "read-only"}}
	a.Secrets = []Secret{{Name: "A"}, {Name: "B"}, {Name: "GITHUB_TOKEN"}}
	a.MCP = []MCP{{Name: "m1", URL: "https://a.example.com/x"}, {Name: "gh", URL: "https://mcp.example.com/mcp", Secret: "GITHUB_TOKEN"}}
	a.Context = []string{"x.md", "y.md"}
	b := validManifest()
	b.Permissions.Egress = []string{h[4], h[2], h[0], h[3], h[1], h[0]}
	b.Permissions.Mounts = []Mount{{".", "read-only"}, {"./b", "read-write"}, {"./a", "read-write"}}
	b.Secrets = []Secret{{Name: "GITHUB_TOKEN"}, {Name: "B"}, {Name: "A"}}
	b.MCP = []MCP{{Name: "gh", URL: "https://mcp.example.com/mcp", Secret: "GITHUB_TOKEN"}, {Name: "m1", URL: "https://a.example.com/x"}}
	b.Context = []string{"y.md", "x.md"}
	if !reflect.DeepEqual(a.RiskLabels(), b.RiskLabels()) {
		t.Fatalf("order changed output:\n%v\n%v", a.RiskLabels(), b.RiskLabels())
	}
}

func TestRiskLabelsSampleBundle(t *testing.T) {
	data, err := os.ReadFile("../cli/testdata/pr-reviewer/capm.yaml")
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []RiskLabel{
		{"context_files", "caution", "Reads context files (1): prompts/review.md"},
		{"mcp_servers", "caution", "Uses MCP servers (1): gh (mcp.example.com)"},
		{"secrets_declared", "caution", "Declares secrets (1): GITHUB_TOKEN"},
		{"mounts_read_only", "info", "Mounts are all read-only (1): ./workspace"},
	}
	if got := m.RiskLabels(); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestRenderRiskLabels(t *testing.T) {
	const head = "Risk labels (computed from the declared manifest; not a review)\n"
	if got := RenderRiskLabels(nil); got != head+"  (no risk labels apply; this is not an endorsement)\n" {
		t.Errorf("empty render = %q", got)
	}
	out := RenderRiskLabels([]RiskLabel{{"x", "high", "bad \x1b[31m‮ text"}})
	if strings.ContainsAny(out, "\x1b‮") {
		t.Errorf("unsanitised: %q", out)
	}
	if !strings.HasPrefix(out, head+"  [high] x: bad") {
		t.Errorf("line form wrong: %q", out)
	}
}
