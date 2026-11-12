package manifest

import (
	"fmt"
	"path"
	"slices"
	"strings"
)

// Risk label severities, most severe first.
const (
	SeverityHigh    = "high"
	SeverityCaution = "caution"
	SeverityInfo    = "info"
)

// Thresholds of the count-based rules.
const (
	maxEgressHosts       = 10 // egress_many_hosts fires above this
	maxSecretEgressHosts = 3  // secret_many_hosts fires above this
)

// RiskLabel is one deterministic exposure label computed from a manifest. It
// states a fact about what the bundle declares; it is not a review, and the
// absence of labels is not an endorsement. Reasons never judge intent.
type RiskLabel struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Reason   string `json:"reason"`
}

func severityRank(s string) int {
	switch s {
	case SeverityHigh:
		return 3
	case SeverityCaution:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// HighestSeverity returns the most severe severity in labels, or "" for none.
func HighestSeverity(labels []RiskLabel) string {
	best := ""
	for _, l := range labels {
		if severityRank(l.Severity) > severityRank(best) {
			best = l.Severity
		}
	}
	return best
}

// RiskLabels computes the labels for m, ordered by severity (high, caution,
// info) then ID, independent of the order of entries in the manifest. The
// slice is never nil.
//
// Rules are limited to what Validate lets through: wildcard egress hosts and
// absolute or ".." mounts are rejected, so there is no rule for them. A mount
// of "." (or anything that cleans to it) passes and is the workspace root.
// Secret destinations follow docs/security-notes.md: a secret named by an MCP
// server goes only to that server; every other declared secret is offered to
// every host in the egress list.
func (m *Manifest) RiskLabels() []RiskLabel {
	labels := []RiskLabel{}
	add := func(id, sev, format string, a ...any) {
		labels = append(labels, RiskLabel{ID: id, Severity: sev, Reason: fmt.Sprintf(format, a...)})
	}

	egress := make([]string, 0, len(m.Permissions.Egress))
	for _, h := range m.Permissions.Egress {
		egress = append(egress, strings.ToLower(h))
	}
	slices.Sort(egress)
	egress = slices.Compact(egress)

	var rw, root []string
	roAll := len(m.Permissions.Mounts) > 0
	var ro []string
	for _, mt := range m.Permissions.Mounts {
		if mt.Mode == "read-write" {
			rw = append(rw, mt.Path)
			roAll = false
		} else if mt.Mode != "read-only" {
			roAll = false
		}
		if path.Clean(mt.Path) == "." {
			root = append(root, fmt.Sprintf("%s (%s)", mt.Path, mt.Mode))
		}
		ro = append(ro, mt.Path)
	}
	slices.Sort(rw)
	slices.Sort(root)
	slices.Sort(ro)

	mcpSecret := map[string]bool{}
	var mcp []string
	for _, c := range m.MCP {
		if c.Secret != "" {
			mcpSecret[c.Secret] = true
		}
		host, _ := MCPHost(c.URL)
		mcp = append(mcp, fmt.Sprintf("%s (%s)", c.Name, host))
	}
	slices.Sort(mcp)

	var secrets, unbound []string
	for _, s := range m.Secrets {
		secrets = append(secrets, s.Name)
		if !mcpSecret[s.Name] {
			unbound = append(unbound, s.Name)
		}
	}
	slices.Sort(secrets)
	secrets = slices.Compact(secrets)
	slices.Sort(unbound)
	unbound = slices.Compact(unbound)

	ctx := slices.Clone(m.Context)
	slices.Sort(ctx)

	// high
	if len(rw) > 0 {
		add("mount_read_write", SeverityHigh, "Mounts read-write (%d): %s", len(rw), strings.Join(rw, ", "))
	}
	if len(root) > 0 {
		add("mount_workspace_root", SeverityHigh, "Mounts the workspace root (%d): %s", len(root), strings.Join(root, ", "))
	}
	if len(egress) > maxEgressHosts {
		add("egress_many_hosts", SeverityHigh, "Declares %d egress hosts (more than %d)", len(egress), maxEgressHosts)
	}
	if len(unbound) > 0 && len(egress) > maxSecretEgressHosts {
		noun := "secrets"
		if len(unbound) == 1 {
			noun = "secret"
		}
		add("secret_many_hosts", SeverityHigh, "Secrets offered to every egress host (%d %s, %d hosts): %s",
			len(unbound), noun, len(egress), strings.Join(unbound, ", "))
	}
	// caution
	if len(secrets) > 0 {
		add("secrets_declared", SeverityCaution, "Declares secrets (%d): %s", len(secrets), strings.Join(secrets, ", "))
	}
	if len(mcp) > 0 {
		add("mcp_servers", SeverityCaution, "Uses MCP servers (%d): %s", len(mcp), strings.Join(mcp, ", "))
	}
	if _, broad := BaseAgentHosts(m.Base.Agent); broad {
		add("base_egress_broad", SeverityCaution, "Base agent %s allows a broad host list that capm does not enumerate", m.Base.Agent)
	}
	if len(ctx) > 0 {
		add("context_files", SeverityCaution, "Reads context files (%d): %s", len(ctx), strings.Join(ctx, ", "))
	}
	// info
	if len(egress) == 0 {
		add("egress_none", SeverityInfo, "Declares egress hosts (0)")
	}
	if roAll {
		add("mounts_read_only", SeverityInfo, "Mounts are all read-only (%d): %s", len(ro), strings.Join(ro, ", "))
	}

	slices.SortFunc(labels, func(a, b RiskLabel) int {
		if r := severityRank(b.Severity) - severityRank(a.Severity); r != 0 {
			return r
		}
		return strings.Compare(a.ID, b.ID)
	})
	return labels
}

// RiskLabelsHeading titles the risk label section everywhere it is shown.
const RiskLabelsHeading = "Risk labels (computed from the declared manifest; not a review)"

// NoRiskLabelsText is shown when no label applies. It is deliberately not a
// verdict: absence of labels is not an endorsement.
const NoRiskLabelsText = "no risk labels apply; this is not an endorsement"

// RenderRiskLabels formats labels as plain text for the terminal. Every string
// goes through DisplaySafe.
func RenderRiskLabels(labels []RiskLabel) string {
	var b strings.Builder
	d := DisplaySafe
	fmt.Fprintf(&b, "%s\n", RiskLabelsHeading)
	if len(labels) == 0 {
		fmt.Fprintf(&b, "  (%s)\n", NoRiskLabelsText)
	}
	for _, l := range labels {
		fmt.Fprintf(&b, "  [%s] %s: %s\n", d(l.Severity), d(l.ID), d(l.Reason))
	}
	return b.String()
}
