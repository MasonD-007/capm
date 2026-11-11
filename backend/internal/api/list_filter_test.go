package api

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MasonD-007/capm/manifest"
)

// publishAs publishes owner/name@version with the given description, as owner.
func publishAs(t *testing.T, e *env, owner, name, version, desc string) {
	t.Helper()
	dir := t.TempDir()
	y := "apiVersion: capm/v0\nkind: Agent\nmetadata: {name: " + name + ", version: " + version + ", description: '" + desc + "'}\n" +
		"base: {agent: claude-code, version: 2.1.292}\ninterface: {type: tty}\n" +
		"model: {api: openai-compatible, requires: {toolCalling: true, minContextTokens: 1000}}\n" +
		"permissions: {egress: [api.github.com]}\n"
	os.WriteFile(filepath.Join(dir, manifest.FileName), []byte(y), 0o644)
	tb, err := manifest.PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	e.user.id, e.user.login = int64(len(owner))*1000+int64(owner[0]), owner
	if c, b := e.do(t, "PUT", "/v1/bundles/"+owner+"/"+name+"/"+version, tb); c != 201 {
		t.Fatalf("publish %s/%s: %d %s", owner, name, c, b)
	}
}

func (e *env) listQ(t *testing.T, query string) (int, []listItem, string) {
	t.Helper()
	c, b := e.do(t, "GET", "/v1/bundles"+query, nil)
	var out []listItem
	if c == 200 {
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("%s: %v: %s", query, err, b)
		}
	}
	return c, out, string(b)
}

func names(items []listItem) string {
	var s []string
	for _, it := range items {
		s = append(s, it.Owner+"/"+it.Name)
	}
	return strings.Join(s, ",")
}

func filterEnv(t *testing.T) *env {
	e, _ := setupCfg(t, Config{})
	publishAs(t, e, "alice", "pr-reviewer", "1.0.0", "Reviews pull requests")
	publishAs(t, e, "alice", "notes", "1.0.0", "Takes notes")
	publishAs(t, e, "bob", "summarizer", "1.0.0", "Summarizes PRs and 100% of docs")
	publishAs(t, e, "carol", "snake", "1.0.0", "Uses snake_case")
	return e
}

func TestListFilterQ(t *testing.T) {
	e := filterEnv(t)
	for _, tc := range []struct{ q, want string }{
		{"reviewer", "alice/pr-reviewer"}, // name
		{"bob", "bob/summarizer"},         // owner
		{"takes", "alice/notes"},          // description
		{"REVIEWER", "alice/pr-reviewer"}, // case-insensitive name
		{"TAKES%20NOTES", "alice/notes"},  // case-insensitive description
		{"ALICE", "alice/notes,alice/pr-reviewer"},
		{"%20%20takes%20%20", "alice/notes"}, // trimmed
		{"%25", "bob/summarizer"},            // literal %: only the description with "100%"
		{"_", "carol/snake"},                 // literal _
		{"%5C", ""},                          // literal backslash
		{"zzz", ""},
	} {
		c, items, body := e.listQ(t, "?q="+tc.q)
		if c != 200 || names(items) != tc.want {
			t.Errorf("q=%s: %d %q, want %q (%s)", tc.q, c, names(items), tc.want, body)
		}
	}
}

func TestListFilterEmptyQIsNoFilter(t *testing.T) {
	e := filterEnv(t)
	for _, q := range []string{"?q=", "?q=%20%20"} {
		if c, items, _ := e.listQ(t, q); c != 200 || len(items) != 4 {
			t.Errorf("%s: %d %q", q, c, names(items))
		}
	}
}

func TestListFilterOwner(t *testing.T) {
	e := filterEnv(t)
	if c, items, _ := e.listQ(t, "?owner=ALICE"); c != 200 || names(items) != "alice/notes,alice/pr-reviewer" {
		t.Errorf("owner: %d %q", c, names(items))
	}
	// exact, not substring
	if c, items, _ := e.listQ(t, "?owner=ali"); c != 200 || len(items) != 0 {
		t.Errorf("owner prefix: %d %q", c, names(items))
	}
	if c, items, _ := e.listQ(t, "?owner=%25"); c != 200 || len(items) != 0 {
		t.Errorf("owner wildcard: %d %q", c, names(items))
	}
}

func TestListFilterOwnerAndQ(t *testing.T) {
	e := filterEnv(t)
	// "pr" matches alice/pr-reviewer by name and bob/summarizer by description.
	if c, items, _ := e.listQ(t, "?q=pr"); c != 200 || names(items) != "alice/pr-reviewer,bob/summarizer" {
		t.Fatalf("q only: %d %q", c, names(items))
	}
	if c, items, _ := e.listQ(t, "?q=pr&owner=bob"); c != 200 || names(items) != "bob/summarizer" {
		t.Errorf("AND: %d %q", c, names(items))
	}
	if c, items, _ := e.listQ(t, "?q=summarizer&owner=alice"); c != 200 || len(items) != 0 {
		t.Errorf("AND disjoint: %d %q", c, names(items))
	}
}

func TestListFilterNoMatchIsEmptyArray(t *testing.T) {
	e := filterEnv(t)
	c, b := e.do(t, "GET", "/v1/bundles?q=nothing-like-this", nil)
	if c != 200 || strings.TrimSpace(string(b)) != "[]" {
		t.Errorf("%d %s", c, b)
	}
}

func TestListFilterQTooLong(t *testing.T) {
	e := filterEnv(t)
	if c, _, b := e.listQ(t, "?q="+strings.Repeat("a", 101)); c != 400 {
		t.Errorf("101 chars: %d %s", c, b)
	}
	if c, _, b := e.listQ(t, "?q="+strings.Repeat("a", 100)); c != 200 {
		t.Errorf("100 chars: %d %s", c, b)
	}
	// Length is counted after trimming, in characters not bytes.
	if c, _, b := e.listQ(t, "?q="+url.QueryEscape(strings.Repeat("é", 100)+"  ")); c != 200 {
		t.Errorf("100 runes: %d %s", c, b)
	}
}

func TestListFilterPagingAfterFiltering(t *testing.T) {
	e, _ := setupCfg(t, Config{})
	publishAs(t, e, "alice", "a-other", "1.0.0", "nope")
	publishAs(t, e, "alice", "b-match", "1.0.0", "nope")
	publishAs(t, e, "bob", "c-other", "1.0.0", "has match inside")
	publishAs(t, e, "carol", "d-other", "1.0.0", "nope")
	publishAs(t, e, "dave", "e-match", "1.0.0", "nope")
	for _, tc := range []struct{ query, want string }{
		{"?q=match", "alice/b-match,bob/c-other,dave/e-match"},
		{"?q=match&limit=1", "alice/b-match"},
		{"?q=match&limit=1&offset=1", "bob/c-other"},
		{"?q=match&limit=2&offset=1", "bob/c-other,dave/e-match"},
		{"?q=match&limit=5&offset=3", ""},
	} {
		if c, items, b := e.listQ(t, tc.query); c != 200 || names(items) != tc.want {
			t.Errorf("%s: %d %q want %q (%s)", tc.query, c, names(items), tc.want, b)
		}
	}
	// Owner-only paging too.
	if _, items, _ := e.listQ(t, "?owner=alice&limit=1&offset=1"); names(items) != "alice/b-match" {
		t.Errorf("owner paging: %q", names(items))
	}
}

func TestListFilterAllYankedMatchesNameAndOwnerNotDescription(t *testing.T) {
	e, _ := setupCfg(t, Config{})
	publishAs(t, e, "alice", "gone", "1.0.0", "secretword")
	e.user.id, e.user.login = int64(len("alice"))*1000+int64('a'), "alice"
	if c, b := e.do(t, "POST", "/v1/bundles/alice/gone/1.0.0/yank", nil); c != 200 {
		t.Fatalf("yank %d %s", c, b)
	}
	if _, items, _ := e.listQ(t, "?q=gone"); len(items) != 1 || items[0].Latest != "" || items[0].Description != "" {
		t.Errorf("by name: %+v", items)
	}
	if _, items, _ := e.listQ(t, "?q=alice"); len(items) != 1 {
		t.Errorf("by owner: %+v", items)
	}
	if _, items, _ := e.listQ(t, "?q=secretword"); len(items) != 0 {
		t.Errorf("by description: %+v", items)
	}
}
