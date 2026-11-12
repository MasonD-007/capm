package api

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/MasonD-007/capm/manifest"
)

// riskBundle packs a bundle whose permissions block is perms.
func riskBundle(t *testing.T, name, version, perms string) []byte {
	t.Helper()
	dir := t.TempDir()
	y := "apiVersion: capm/v0\nkind: Agent\nmetadata: {name: " + name + ", version: " + version + "}\n" +
		"base: {agent: claude-code, version: 2.1.292}\ninterface: {type: tty}\n" +
		"model: {api: openai-compatible, requires: {toolCalling: true, minContextTokens: 1000}}\n" +
		"permissions: " + perms + "\n"
	os.WriteFile(filepath.Join(dir, manifest.FileName), []byte(y), 0o644)
	b, err := manifest.PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type riskListItem struct {
	Name       string                `json:"name"`
	Latest     string                `json:"latest"`
	Risk       *string               `json:"risk"`
	RiskLabels *[]manifest.RiskLabel `json:"riskLabels"`
}

func (e *env) riskList(t *testing.T, query string) map[string]riskListItem {
	t.Helper()
	c, b := e.do(t, "GET", "/v1/bundles"+query, nil)
	if c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	var items []riskListItem
	if err := json.Unmarshal(b, &items); err != nil {
		t.Fatal(err)
	}
	out := map[string]riskListItem{}
	for _, it := range items {
		out[it.Name] = it
	}
	return out
}

func TestListRiskLabels(t *testing.T) {
	e := adminEnv(t)
	for name, perms := range map[string]string{
		"plain": "{egress: [api.github.com]}",
		"rw":    "{egress: [api.github.com], mounts: [{path: ./workspace, mode: read-write}]}",
		"ro":    "{egress: [api.github.com], mounts: [{path: ./workspace, mode: read-only}]}",
	} {
		if c, b := e.do(t, "PUT", "/v1/bundles/alice/"+name+"/1.0.0", riskBundle(t, name, "1.0.0", perms)); c != 201 {
			t.Fatalf("%s: %d %s", name, c, b)
		}
	}
	// A newer version of "plain" that is yanked must not be the source.
	if c, b := e.do(t, "PUT", "/v1/bundles/alice/plain/2.0.0",
		riskBundle(t, "plain", "2.0.0", "{egress: [api.github.com], mounts: [{path: ., mode: read-write}]}")); c != 201 {
		t.Fatalf("%d %s", c, b)
	}
	if c, b := e.do(t, "POST", "/v1/bundles/alice/plain/2.0.0/yank", nil); c != 200 {
		t.Fatalf("yank %d %s", c, b)
	}
	e.asNobody()

	items := e.riskList(t, "")
	for _, tc := range []struct {
		name, risk string
		ids        []string
	}{
		{"plain", "", []string{}},
		{"rw", "high", []string{"mount_read_write"}},
		{"ro", "info", []string{"mounts_read_only"}},
	} {
		it, ok := items[tc.name]
		if !ok || it.Risk == nil || it.RiskLabels == nil {
			t.Fatalf("%s: fields must be present: %+v", tc.name, it)
		}
		if *it.Risk != tc.risk {
			t.Errorf("%s risk = %q, want %q", tc.name, *it.Risk, tc.risk)
		}
		got := []string{}
		for _, l := range *it.RiskLabels {
			got = append(got, l.ID)
		}
		if !reflect.DeepEqual(got, tc.ids) {
			t.Errorf("%s labels = %v, want %v", tc.name, got, tc.ids)
		}
	}
	// Search results carry them too.
	if it := e.riskList(t, "?q=rw")["rw"]; it.Risk == nil || *it.Risk != "high" {
		t.Errorf("search item: %+v", it)
	}
	// An empty set is [] on the wire, never null.
	_, raw := e.do(t, "GET", "/v1/bundles?q=plain", nil)
	var generic []map[string]json.RawMessage
	json.Unmarshal(raw, &generic)
	if string(generic[0]["riskLabels"]) != "[]" || string(generic[0]["risk"]) != `""` {
		t.Errorf("empty wire form: %s", raw)
	}
}

func TestListRiskLabelsNoInstallableVersion(t *testing.T) {
	e := adminEnv(t)
	perms := "{egress: [api.github.com], mounts: [{path: ./w, mode: read-write}]}"
	e.do(t, "PUT", "/v1/bundles/alice/yanked/1.0.0", riskBundle(t, "yanked", "1.0.0", perms))
	e.do(t, "POST", "/v1/bundles/alice/yanked/1.0.0/yank", nil)
	e.do(t, "PUT", "/v1/bundles/alice/removed/1.0.0", riskBundle(t, "removed", "1.0.0", perms))
	e.asAdmin()
	if c, b := e.do(t, "POST", "/v1/admin/bundles/alice/removed/1.0.0/remove", reason("takedown")); c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	e.asNobody()
	_, raw := e.do(t, "GET", "/v1/bundles", nil)
	var generic []map[string]json.RawMessage
	json.Unmarshal(raw, &generic)
	if len(generic) != 2 {
		t.Fatalf("%s", raw)
	}
	for _, it := range generic {
		if string(it["riskLabels"]) != "[]" || string(it["risk"]) != `""` || string(it["latest"]) != `""` {
			t.Errorf("no installable version must give empty labels: %s", raw)
		}
	}
}

func TestMetadataRiskLabels(t *testing.T) {
	e := adminEnv(t)
	if c, b := e.do(t, "PUT", "/v1/bundles/alice/rw/1.0.0",
		riskBundle(t, "rw", "1.0.0", "{egress: [api.github.com], mounts: [{path: ./workspace, mode: read-write}]}")); c != 201 {
		t.Fatalf("%d %s", c, b)
	}
	if c, b := e.do(t, "PUT", "/v1/bundles/alice/plain/1.0.0", riskBundle(t, "plain", "1.0.0", "{egress: [api.github.com]}")); c != 201 {
		t.Fatalf("%d %s", c, b)
	}
	e.asNobody()
	var m struct {
		RiskLabels *[]manifest.RiskLabel `json:"riskLabels"`
	}
	_, b := e.do(t, "GET", "/v1/bundles/alice/rw/1.0.0", nil)
	json.Unmarshal(b, &m)
	want := []manifest.RiskLabel{{ID: "mount_read_write", Severity: "high", Reason: "Mounts read-write (1): ./workspace"}}
	if m.RiskLabels == nil || !reflect.DeepEqual(*m.RiskLabels, want) {
		t.Errorf("rw metadata: %s", b)
	}
	_, b = e.do(t, "GET", "/v1/bundles/alice/plain/1.0.0", nil)
	var g map[string]json.RawMessage
	json.Unmarshal(b, &g)
	if string(g["riskLabels"]) != "[]" {
		t.Errorf("plain metadata: %s", b)
	}
	// Existing fields are still there.
	for _, f := range []string{"ownerId", "version", "digest", "yanked", "manifest", "summary", "createdAt"} {
		if _, ok := g[f]; !ok {
			t.Errorf("metadata lost %s", f)
		}
	}
}

func TestRemovedVersionMetadataStays410WithoutLabels(t *testing.T) {
	e := adminEnv(t)
	e.do(t, "PUT", "/v1/bundles/alice/rw/1.0.0",
		riskBundle(t, "rw", "1.0.0", "{egress: [api.github.com], mounts: [{path: ./w, mode: read-write}]}"))
	e.asAdmin()
	e.do(t, "POST", "/v1/admin/bundles/alice/rw/1.0.0/remove", reason("takedown"))
	c, b := e.do(t, "GET", "/v1/bundles/alice/rw/1.0.0", nil)
	if c != 410 {
		t.Fatalf("%d %s", c, b)
	}
	var g map[string]json.RawMessage
	json.Unmarshal(b, &g)
	if _, ok := g["riskLabels"]; ok {
		t.Errorf("removed version must serve no labels: %s", b)
	}
}
