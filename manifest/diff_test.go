package manifest

import (
	"reflect"
	"strings"
	"testing"
)

func TestDiffIdenticalAndOrderInsensitive(t *testing.T) {
	a, b := validManifest(), validManifest()
	a.Permissions.Egress = []string{"a.example.com", "B.example.com"}
	b.Permissions.Egress = []string{"b.EXAMPLE.com", "A.example.com"}
	a.Permissions.Mounts = []Mount{{"./x", "read-only"}, {"./y", "read-write"}}
	b.Permissions.Mounts = []Mount{{"./y", "read-write"}, {"./x", "read-only"}}
	a.Secrets = []Secret{{Name: "A"}, {Name: "B"}}
	b.Secrets = []Secret{{Name: "B", Description: "only the description differs"}, {Name: "A"}}
	a.Context = []string{"a.md", "b.md"}
	b.Context = []string{"b.md", "a.md"}
	d := DiffPermissions(a, b)
	if !d.Empty() || d.Escalates() || d.Render() != "" {
		t.Fatalf("expected empty diff, got %+v render=%q", d, d.Render())
	}
	if !DiffPermissions(nil, nil).Empty() {
		t.Error("nil/nil must be empty")
	}
}

func TestDiffEgress(t *testing.T) {
	a, b := validManifest(), validManifest()
	a.Permissions.Egress = []string{"keep.example.com", "gone.example.com"}
	b.Permissions.Egress = []string{"KEEP.example.com", "new.example.com"}
	d := DiffPermissions(a, b)
	if !reflect.DeepEqual(d.Egress.Added, []string{"new.example.com"}) || !reflect.DeepEqual(d.Egress.Removed, []string{"gone.example.com"}) {
		t.Fatalf("egress: %+v", d.Egress)
	}
	if !d.Escalates() || d.Empty() {
		t.Error("added host must escalate")
	}
	// Removed only: informational.
	a.Permissions.Egress = []string{"x.example.com", "y.example.com"}
	b.Permissions.Egress = []string{"x.example.com"}
	d = DiffPermissions(a, b)
	if d.Empty() || d.Escalates() {
		t.Errorf("removed-only: empty=%v escalates=%v", d.Empty(), d.Escalates())
	}
}

func TestDiffMounts(t *testing.T) {
	for _, c := range []struct {
		from, to string
		escalate bool
	}{{"read-only", "read-write", true}, {"read-write", "read-only", false}} {
		a, b := validManifest(), validManifest()
		a.Permissions.Mounts = []Mount{{"./w", c.from}}
		b.Permissions.Mounts = []Mount{{"./w", c.to}}
		d := DiffPermissions(a, b)
		if len(d.Mounts.Added)+len(d.Mounts.Removed) != 0 || len(d.Mounts.Changed) != 1 {
			t.Fatalf("%s->%s: %+v", c.from, c.to, d.Mounts)
		}
		ch := d.Mounts.Changed[0]
		if ch.Key != "./w" || ch.Old != c.from || ch.New != c.to || d.Escalates() != c.escalate || ch.Escalation != c.escalate {
			t.Errorf("%s->%s: %+v escalates=%v", c.from, c.to, ch, d.Escalates())
		}
	}
	// A different path is a removal plus an addition.
	a, b := validManifest(), validManifest()
	a.Permissions.Mounts = []Mount{{"./a", "read-only"}}
	b.Permissions.Mounts = []Mount{{"./b", "read-only"}}
	d := DiffPermissions(a, b)
	if len(d.Mounts.Added) != 1 || len(d.Mounts.Removed) != 1 || len(d.Mounts.Changed) != 0 || !d.Escalates() {
		t.Errorf("path change: %+v", d.Mounts)
	}
}

func TestDiffSecretsMCPBaseContext(t *testing.T) {
	a, b := validManifest(), validManifest()
	b.Secrets = append(b.Secrets, Secret{Name: "NEW"})
	d := DiffPermissions(a, b)
	if !reflect.DeepEqual(d.Secrets.Added, []string{"NEW"}) || !d.Escalates() {
		t.Errorf("secret added: %+v", d.Secrets)
	}

	for name, mut := range map[string]func(*MCP){
		"url":    func(c *MCP) { c.URL = "https://other.example.com/mcp" },
		"secret": func(c *MCP) { c.Secret = "OTHER" },
	} {
		a, b = validManifest(), validManifest()
		mut(&b.MCP[0])
		d = DiffPermissions(a, b)
		if len(d.MCP.Changed) != 1 || d.MCP.Changed[0].Key != "gh" || !d.Escalates() || len(d.MCP.Added) != 0 {
			t.Errorf("mcp %s: %+v", name, d.MCP)
		}
	}

	a, b = validManifest(), validManifest()
	b.Base.Version = "2.0.0"
	d = DiffPermissions(a, b)
	if len(d.Base.Changed) != 1 || !d.Escalates() || !strings.Contains(d.Render(), "claude-code 1.0.0 -> claude-code 2.0.0") {
		t.Errorf("base version: %+v\n%s", d.Base, d.Render())
	}
	b.Base = Base{Agent: "opencode"}
	if d = DiffPermissions(a, b); !d.Escalates() {
		t.Error("base agent change must escalate")
	}

	a, b = validManifest(), validManifest()
	b.Context = []string{"docs/readme.md", "new.md"}
	d = DiffPermissions(a, b)
	if !reflect.DeepEqual(d.Context.Added, []string{"new.md"}) || !d.Escalates() {
		t.Errorf("context: %+v", d.Context)
	}
	b.Context = nil
	if d = DiffPermissions(a, b); d.Escalates() || len(d.Context.Removed) != 1 {
		t.Errorf("context removed: %+v", d.Context)
	}
}

func TestDiffRender(t *testing.T) {
	a, b := validManifest(), validManifest()
	a.Permissions.Egress = []string{"gone.example.com"}
	b.Permissions.Egress = []string{"z.example.com", "new.example.com"}
	b.Permissions.Mounts[0].Mode = "read-write"
	b.Secrets = append(b.Secrets, Secret{Name: "EVIL\x1b[31m"})
	out := DiffPermissions(a, b).Render()
	want := "Network egress\n" +
		"  + new.example.com\n" +
		"  + z.example.com\n" +
		"  - gone.example.com\n" +
		"Mounts\n" +
		"  ~ ./workspace: read-only -> read-write (more access)\n" +
		"Secrets\n" +
		"  + EVIL�[31m\n"
	if out != want {
		t.Errorf("render:\n%s\nwant:\n%s", out, want)
	}
	if strings.Contains(out, "\x1b") {
		t.Error("control char leaked")
	}
	if out != DiffPermissions(a, b).Render() {
		t.Error("not deterministic")
	}
}
