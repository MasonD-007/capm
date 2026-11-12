package manifest

import (
	"fmt"
	"slices"
	"strings"
)

// Change is one item present in both manifests whose value differs: a mount
// whose mode changed, an MCP server whose URL or secret changed, or the base
// agent. Escalation marks a change that gives the bundle more reach.
type Change struct {
	Key        string
	Old, New   string
	Escalation bool
}

// SectionDiff is the difference in one permission section. Added and Removed
// hold display strings; all three slices are sorted.
type SectionDiff struct {
	Added   []string
	Removed []string
	Changed []Change
}

func (s SectionDiff) empty() bool {
	return len(s.Added)+len(s.Removed)+len(s.Changed) == 0
}

// PermissionDiff is what changed in the permission surface between two
// manifests: egress hosts, mounts, secrets, MCP servers, base agent and
// context files. Metadata, model and descriptions are not permissions and are
// ignored. Comparison is order-insensitive; egress hosts compare
// case-insensitively.
type PermissionDiff struct {
	Egress  SectionDiff
	Mounts  SectionDiff // keyed by path; value is the mode
	Secrets SectionDiff // keyed by name
	MCP     SectionDiff // keyed by name; value is URL plus secret
	Base    SectionDiff // at most one Change, never Added/Removed
	Context SectionDiff
}

func (d PermissionDiff) sections() []SectionDiff {
	return []SectionDiff{d.Egress, d.Mounts, d.Secrets, d.MCP, d.Base, d.Context}
}

// Empty reports whether nothing in the permission surface changed.
func (d PermissionDiff) Empty() bool {
	for _, s := range d.sections() {
		if !s.empty() {
			return false
		}
	}
	return true
}

// Escalates reports whether the new manifest gives the bundle more than the
// old one: anything Added, a mount going to a mode other than read-only, an
// MCP server re-pointed, or a different base agent.
func (d PermissionDiff) Escalates() bool {
	for _, s := range d.sections() {
		if len(s.Added) > 0 {
			return true
		}
		for _, c := range s.Changed {
			if c.Escalation {
				return true
			}
		}
	}
	return false
}

// DiffPermissions compares the permission surface of old and new. A nil
// manifest is treated as declaring nothing.
func DiffPermissions(old, new *Manifest) PermissionDiff {
	if old == nil {
		old = &Manifest{}
	}
	if new == nil {
		new = &Manifest{}
	}
	var d PermissionDiff
	d.Egress = diffMaps(egressMap(old), egressMap(new), nil)
	d.Mounts = diffMaps(mountMap(old), mountMap(new), func(_, _, to string) bool { return to != "read-only" })
	d.Secrets = diffMaps(secretMap(old), secretMap(new), nil)
	d.MCP = diffMaps(mcpMap(old), mcpMap(new), func(_, _, _ string) bool { return true })
	d.Context = diffMaps(setMap(old.Context, false), setMap(new.Context, false), nil)
	if ob, nb := baseString(old.Base), baseString(new.Base); ob != nb {
		d.Base.Changed = []Change{{Key: "agent", Old: ob, New: nb, Escalation: true}}
	}
	return d
}

func baseString(b Base) string {
	return strings.TrimSpace(b.Agent + " " + b.Version)
}

func setMap(items []string, fold bool) map[string]string {
	m := map[string]string{}
	for _, s := range items {
		if fold {
			s = strings.ToLower(s)
		}
		m[s] = ""
	}
	return m
}

func egressMap(m *Manifest) map[string]string { return setMap(m.Permissions.Egress, true) }

func mountMap(m *Manifest) map[string]string {
	out := map[string]string{}
	for _, mt := range m.Permissions.Mounts {
		out[mt.Path] = mt.Mode
	}
	return out
}

func secretMap(m *Manifest) map[string]string {
	out := map[string]string{}
	for _, s := range m.Secrets {
		out[s.Name] = ""
	}
	return out
}

func mcpMap(m *Manifest) map[string]string {
	out := map[string]string{}
	for _, c := range m.MCP {
		v := c.URL
		if c.Secret != "" {
			v += " using secret " + c.Secret
		}
		out[c.Name] = v
	}
	return out
}

// diffMaps compares two key->value maps. Added/Removed show "key (value)" or
// just the key when the value is empty. escalates decides, for a key present
// in both with a different value, whether the change is an escalation; nil
// means value changes cannot occur.
func diffMaps(old, new map[string]string, escalates func(key, from, to string) bool) SectionDiff {
	var s SectionDiff
	show := func(k, v string) string {
		if v == "" {
			return k
		}
		return fmt.Sprintf("%s (%s)", k, v)
	}
	for k, nv := range new {
		ov, ok := old[k]
		switch {
		case !ok:
			s.Added = append(s.Added, show(k, nv))
		case ov != nv:
			c := Change{Key: k, Old: ov, New: nv}
			if escalates != nil {
				c.Escalation = escalates(k, ov, nv)
			}
			s.Changed = append(s.Changed, c)
		}
	}
	for k, ov := range old {
		if _, ok := new[k]; !ok {
			s.Removed = append(s.Removed, show(k, ov))
		}
	}
	slices.Sort(s.Added)
	slices.Sort(s.Removed)
	slices.SortFunc(s.Changed, func(a, b Change) int { return strings.Compare(a.Key, b.Key) })
	return s
}

// Render formats the diff as grouped "+" (added), "-" (removed) and "~"
// (changed) lines in a fixed section order. Every manifest-supplied string
// goes through DisplaySafe. An empty diff renders as "".
func (d PermissionDiff) Render() string {
	var b strings.Builder
	sec := func(title string, s SectionDiff, keyed bool) {
		if s.empty() {
			return
		}
		fmt.Fprintf(&b, "%s\n", title)
		for _, a := range s.Added {
			fmt.Fprintf(&b, "  + %s\n", DisplaySafe(a))
		}
		for _, r := range s.Removed {
			fmt.Fprintf(&b, "  - %s\n", DisplaySafe(r))
		}
		for _, c := range s.Changed {
			mark := ""
			if c.Escalation {
				mark = " (more access)"
			}
			if keyed {
				fmt.Fprintf(&b, "  ~ %s: %s -> %s%s\n", DisplaySafe(c.Key), DisplaySafe(c.Old), DisplaySafe(c.New), mark)
			} else {
				fmt.Fprintf(&b, "  ~ %s -> %s%s\n", DisplaySafe(c.Old), DisplaySafe(c.New), mark)
			}
		}
	}
	sec("Network egress", d.Egress, true)
	sec("Mounts", d.Mounts, true)
	sec("Secrets", d.Secrets, true)
	sec("MCP servers", d.MCP, true)
	sec("Base agent", d.Base, false)
	sec("Context files", d.Context, true)
	return b.String()
}
