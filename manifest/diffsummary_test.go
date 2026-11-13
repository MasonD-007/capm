package manifest

import "testing"

func TestSummary(t *testing.T) {
	cases := []struct {
		name string
		edit func(m *Manifest)
		want string
	}{
		{"nothing", func(m *Manifest) {}, "no permission changes"},
		{"metadata only", func(m *Manifest) { m.Metadata.Description = "other"; m.Metadata.Version = "0.2.0" }, "no permission changes"},
		{"one host", func(m *Manifest) { m.Permissions.Egress = append(m.Permissions.Egress, "x.example.com") }, "adds 1 egress host"},
		{"adds and widens", func(m *Manifest) {
			m.Permissions.Egress = append(m.Permissions.Egress, "x.example.com", "y.example.com")
			m.Secrets = append(m.Secrets, Secret{Name: "OTHER"})
			m.Permissions.Mounts[0].Mode = "read-write"
		}, "adds 2 egress hosts, 1 secret; widens 1 mount"},
		{"removal after escalation", func(m *Manifest) {
			m.Permissions.Egress = []string{"new.example.com"} // api.github.com removed, one added
			m.Context = nil
		}, "adds 1 egress host; removes 1 egress host, 1 context file"},
		{"only removals", func(m *Manifest) { m.Permissions.Mounts = nil; m.Secrets = nil; m.MCP = nil }, "removes 1 mount, 1 secret, 1 MCP server"},
		{"mcp repointed is widening", func(m *Manifest) { m.MCP[0].URL = "https://other.example.com/mcp" }, "widens 1 MCP server"},
		{"base agent", func(m *Manifest) { m.Base.Agent = "codex" }, "changes the base agent"},
		{"base agent and host", func(m *Manifest) {
			m.Base.Agent = "codex"
			m.Permissions.Egress = append(m.Permissions.Egress, "x.example.com")
		}, "adds 1 egress host; changes the base agent"},
		{"context added", func(m *Manifest) { m.Context = append(m.Context, "docs/b.md", "docs/c.md") }, "adds 2 context files"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			old, nw := validManifest(), validManifest()
			c.edit(nw)
			if got := DiffPermissions(old, nw).Summary(); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
	// Tightening a mount (read-write -> read-only) is a non-escalating change.
	old, nw := validManifest(), validManifest()
	old.Permissions.Mounts[0].Mode = "read-write"
	if got := DiffPermissions(old, nw).Summary(); got != "changes 1 mount" {
		t.Fatalf("tightened: %q", got)
	}
}

func TestSummaryDeterministic(t *testing.T) {
	old, nw := validManifest(), validManifest()
	nw.Permissions.Egress = append(nw.Permissions.Egress, "z.example.com", "a.example.com")
	nw.Secrets = append(nw.Secrets, Secret{Name: "B"}, Secret{Name: "A"})
	want := DiffPermissions(old, nw).Summary()
	for i := 0; i < 20; i++ {
		if got := DiffPermissions(old, nw).Summary(); got != want {
			t.Fatalf("run %d: %q != %q", i, got, want)
		}
	}
}
