package manifest

import (
	"fmt"
	"strings"
)

// Summary is a one-line, count-only description of the diff, for tables:
//
//	adds 2 egress hosts, 1 secret; widens 1 mount
//
// Clauses are separated by "; " and always in this order, so output is
// deterministic and anything that gives the bundle more reach comes first:
// adds, widens (a mount made writable, an MCP server re-pointed), a changed
// base agent, then removes, then other changes (a mount made read-only).
// Within a clause the sections follow the order of Render. An empty diff is
// "no permission changes". No manifest-supplied text appears in the result.
func (d PermissionDiff) Summary() string {
	type sec struct {
		d              SectionDiff
		singular, plur string
	}
	secs := []sec{
		{d.Egress, "egress host", "egress hosts"},
		{d.Mounts, "mount", "mounts"},
		{d.Secrets, "secret", "secrets"},
		{d.MCP, "MCP server", "MCP servers"},
		{d.Context, "context file", "context files"},
	}
	count := func(n int, s sec) string {
		if n == 1 {
			return "1 " + s.singular
		}
		return fmt.Sprintf("%d %s", n, s.plur)
	}
	clause := func(verb string, n func(SectionDiff) int) string {
		var parts []string
		for _, s := range secs {
			if c := n(s.d); c > 0 {
				parts = append(parts, count(c, s))
			}
		}
		if len(parts) == 0 {
			return ""
		}
		return verb + " " + strings.Join(parts, ", ")
	}
	changed := func(escalation bool) func(SectionDiff) int {
		return func(s SectionDiff) int {
			n := 0
			for _, c := range s.Changed {
				if c.Escalation == escalation {
					n++
				}
			}
			return n
		}
	}

	var out []string
	add := func(s string) {
		if s != "" {
			out = append(out, s)
		}
	}
	add(clause("adds", func(s SectionDiff) int { return len(s.Added) }))
	add(clause("widens", changed(true)))
	if len(d.Base.Changed) > 0 {
		add("changes the base agent")
	}
	add(clause("removes", func(s SectionDiff) int { return len(s.Removed) }))
	add(clause("changes", changed(false)))
	if len(out) == 0 {
		return "no permission changes"
	}
	return strings.Join(out, "; ")
}
