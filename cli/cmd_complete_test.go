package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type completeFixture struct {
	srv      *httptest.Server
	hits     atomic.Int32
	sawAuth  atomic.Bool
	sawQuery atomic.Value // last RawQuery
	bundles  []map[string]any
	versions map[string][]map[string]any // "owner/name" -> versions
	delay    time.Duration
}

func newCompleteFixture(t *testing.T) *completeFixture {
	t.Helper()
	f := &completeFixture{versions: map[string][]map[string]any{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		if r.Header.Get("Authorization") != "" {
			f.sawAuth.Store(true)
		}
		f.sawQuery.Store(r.URL.RawQuery)
		if f.delay > 0 {
			select {
			case <-time.After(f.delay):
			case <-r.Context().Done():
				return
			}
		}
		switch {
		case r.URL.Path == "/v1/bundles":
			json.NewEncoder(w).Encode(f.bundles)
		case strings.HasPrefix(r.URL.Path, "/v1/bundles/"):
			key := strings.TrimPrefix(r.URL.Path, "/v1/bundles/")
			if vs, ok := f.versions[key]; ok {
				json.NewEncoder(w).Encode(vs)
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *completeFixture) env(t *testing.T) env {
	return env{registry: f.srv.URL, credDir: filepath.Join(t.TempDir(), "capm")}
}

// complete runs `capm __complete args...` and returns stdout lines, failing
// the test on a non-zero exit or any stderr output.
func complete(t *testing.T, e env, args ...string) []string {
	t.Helper()
	var out, errb bytes.Buffer
	code := runEnv(append([]string{"__complete"}, args...), &out, &errb, e)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if errb.Len() != 0 {
		t.Fatalf("stderr is not empty: %q", errb.String())
	}
	var lines []string
	for _, l := range strings.Split(out.String(), "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

func recordKnown(t *testing.T, e env, registry, owner, name, version string) {
	t.Helper()
	err := newKnownStore(e, io.Discard).update(registry, owner, name, func(r *knownRecord) {
		if version != "" {
			r.LastRun = &lastRun{Version: version}
		}
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCompleteBundlesFromKnownThenRegistry(t *testing.T) {
	f := newCompleteFixture(t)
	f.bundles = []map[string]any{
		{"owner": "alice", "name": "reviewer", "latest": "1.0.0"},
		{"owner": "alice", "name": "alpha"}, // also known: listed once
		{"owner": "bob", "name": "alpine"},
		{"owner": "carol", "name": "zzz"}, // does not start with the prefix
	}
	e := f.env(t)
	recordKnown(t, e, f.srv.URL, "alice", "alpha", "")
	recordKnown(t, e, f.srv.URL, "other", "alpha", "")
	recordKnown(t, e, "https://elsewhere.example", "alice", "elsewhere", "") // another registry
	got := complete(t, e, "bundles", "al")
	want := []string{"alice/alpha", "alice/reviewer"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	q, _ := f.sawQuery.Load().(string)
	if !strings.Contains(q, "q=al") || !strings.Contains(q, "limit=20") {
		t.Errorf("search query %q does not ask q=al&limit=20", q)
	}
}

func TestCompleteBundlesOwnerPrefixUsesOwnerFilter(t *testing.T) {
	f := newCompleteFixture(t)
	f.bundles = []map[string]any{{"owner": "alice", "name": "reviewer"}, {"owner": "alice", "name": "writer"}}
	got := complete(t, f.env(t), "bundles", "alice/re")
	if !slices.Equal(got, []string{"alice/reviewer"}) {
		t.Errorf("got %q", got)
	}
	if q, _ := f.sawQuery.Load().(string); !strings.Contains(q, "owner=alice") || !strings.Contains(q, "limit=20") {
		t.Errorf("query %q", q)
	}
}

func TestCompleteBundlesKnownIsOfflineAndInstant(t *testing.T) {
	e := env{registry: "http://127.0.0.1:1", credDir: filepath.Join(t.TempDir(), "capm")}
	recordKnown(t, e, e.registry, "alice", "one", "")
	start := time.Now()
	got := complete(t, e, "bundles", "ali")
	if !slices.Equal(got, []string{"alice/one"}) {
		t.Errorf("got %q", got)
	}
	if d := time.Since(start); d > 900*time.Millisecond {
		t.Errorf("took %v with the registry refusing connections", d)
	}
}

func TestCompleteBundlesTimeoutPrintsWhatItHas(t *testing.T) {
	f := newCompleteFixture(t)
	f.delay = 5 * time.Second
	f.bundles = []map[string]any{{"owner": "alice", "name": "slow"}}
	e := f.env(t)
	recordKnown(t, e, f.srv.URL, "alice", "known", "")
	start := time.Now()
	got := complete(t, e, "bundles", "alice/")
	d := time.Since(start)
	if d > 1800*time.Millisecond {
		t.Errorf("took %v, want about 1s", d)
	}
	if d < 800*time.Millisecond {
		t.Errorf("returned after %v, before the 1s budget: the registry was not waited for", d)
	}
	if !slices.Equal(got, []string{"alice/known"}) {
		t.Errorf("got %q, want only the known bundle", got)
	}
}

func TestCompleteBundlesRegistryErrorsAreSilent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"boom"}`, 500)
	}))
	defer srv.Close()
	if got := complete(t, env{registry: srv.URL, credDir: t.TempDir()}, "bundles", "a"); len(got) != 0 {
		t.Errorf("got %q", got)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "not json") }))
	defer bad.Close()
	if got := complete(t, env{registry: bad.URL, credDir: t.TempDir()}, "bundles", "a"); len(got) != 0 {
		t.Errorf("got %q", got)
	}
}

func TestCompleteVersions(t *testing.T) {
	f := newCompleteFixture(t)
	f.versions["alice/x"] = []map[string]any{
		{"version": "1.0.0"},
		{"version": "1.1.0", "yanked": true},
		{"version": "1.2.0", "removed": true},
		{"version": "2.0.0"},
		{"version": "1.0 evil"},
		{"version": "$(id)"},
	}
	e := f.env(t)
	recordKnown(t, e, f.srv.URL, "alice", "x", "0.9.0")
	got := complete(t, e, "bundles", "alice/x@")
	want := []string{"alice/x@0.9.0", "alice/x@1.0.0", "alice/x@1.1.0", "alice/x@2.0.0"}
	if !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := complete(t, e, "bundles", "alice/x@1"); !slices.Equal(got, []string{"alice/x@1.0.0", "alice/x@1.1.0"}) {
		t.Errorf("prefix @1: got %q", got)
	}
	if got := complete(t, e, "bundles", "alice/nosuch@"); len(got) != 0 {
		t.Errorf("404: got %q", got)
	}
}

func TestCompleteHostileRegistryOutputIsDropped(t *testing.T) {
	f := newCompleteFixture(t)
	hostile := []string{
		"has space", "$(touch pwned)", "`id`", "semi;colon", "new\nline", "esc\x1b[31m", "pipe|x", "amp&x",
		"quote'x", `dq"x`, "glob*", "q?", "br[a]", "tab\tx", "back\\slash", "lt<x", "gt>x", "bang!", "hash#", "tilde~x",
		"-leading", ".dot..dot", "ünï", "nul\x00x", "bidi‮x", "a/b",
	}
	f.bundles = []map[string]any{{"owner": "alice", "name": "good"}}
	f.versions["alice/good"] = []map[string]any{{"version": "1.0.0"}}
	for _, h := range hostile {
		f.bundles = append(f.bundles, map[string]any{"owner": "alice", "name": h}, map[string]any{"owner": h, "name": "x"})
		f.versions["alice/good"] = append(f.versions["alice/good"], map[string]any{"version": h})
	}
	for _, args := range [][]string{{"bundles", ""}, {"bundles", "alice/"}, {"bundles", "alice/good@"}} {
		e := f.env(t)
		var out, errb bytes.Buffer
		if code := runEnv(append([]string{"__complete"}, args...), &out, &errb, e); code != 0 || errb.Len() != 0 {
			t.Fatalf("%v: exit %d stderr %q", args, code, errb.String())
		}
		for _, l := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
			if l == "" {
				continue
			}
			for _, r := range l {
				if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-/@+", r)) {
					t.Errorf("%v: line %q contains %q", args, l, r)
				}
			}
			if strings.Contains(l, "..") {
				t.Errorf("%v: line %q contains ..", args, l)
			}
		}
		if strings.Contains(out.String(), "\x1b") || strings.Contains(out.String(), "pwned") {
			t.Errorf("%v: hostile text survived: %q", args, out.String())
		}
	}
	got := complete(t, f.env(t), "bundles", "alice/")
	if !slices.Equal(got, []string{"alice/good"}) {
		t.Errorf("only the well-formed bundle should survive, got %q", got)
	}
}

func TestCompleteBundlesNeverSendsTokenWritesFilesOrNotifies(t *testing.T) {
	f := newCompleteFixture(t)
	f.bundles = []map[string]any{{"owner": "alice", "name": "one"}}
	e := f.env(t)
	e.getenv = func(string) string { return "" }
	// A stored login must not be read into a request.
	if err := saveCreds(e, credentials{Registry: f.srv.URL, Login: "alice", Token: "SECRET-TOKEN"}); err != nil {
		t.Fatal(err)
	}
	recordKnown(t, e, f.srv.URL, "alice", "known", "")
	before := dirListing(t, e.credDir)

	// The update notice is armed: a semver build, a terminal, a latest-release URL.
	notice := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the update check ran for __complete: %s", r.URL)
	}))
	defer notice.Close()
	old := version
	version = "1.0.0"
	defer func() { version = old }()
	e.upd = updateEnv{latestURL: notice.URL + "/releases/tag/v9.9.9", stderrTTY: func() bool { return true }}

	got := complete(t, e, "bundles", "alice/")
	if !slices.Equal(got, []string{"alice/known", "alice/one"}) {
		t.Errorf("got %q", got)
	}
	if f.sawAuth.Load() {
		t.Error("an Authorization header was sent")
	}
	if after := dirListing(t, e.credDir); !slices.Equal(before, after) {
		t.Errorf("files changed: %v -> %v", before, after)
	}
	if _, err := os.Stat(filepath.Join(e.credDir, "update-check.json")); err == nil {
		t.Error("update-check.json was written")
	}
}

func dirListing(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil {
			out = append(out, p+" "+info.ModTime().String()+" "+string(rune(info.Size())))
		}
		return nil
	})
	return out
}

func TestCompleteDoesNotCreateConfigDir(t *testing.T) {
	f := newCompleteFixture(t)
	e := f.env(t)
	complete(t, e, "bundles", "a")
	if _, err := os.Stat(e.credDir); err == nil {
		t.Error("the config directory was created")
	}
}

func TestCompleteCorruptKnownIsSilent(t *testing.T) {
	e := env{registry: "http://127.0.0.1:1", credDir: t.TempDir()}
	if err := os.WriteFile(filepath.Join(e.credDir, "known.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := complete(t, e, "bundles", "a"); len(got) != 0 {
		t.Errorf("got %q", got)
	}
}

func TestCompleteUnknownArgumentsPrintNothing(t *testing.T) {
	f := newCompleteFixture(t)
	f.bundles = []map[string]any{{"owner": "alice", "name": "one"}}
	for _, args := range [][]string{
		{}, {"nosuch"}, {"bundles"}, {"bundles", "a", "b"}, {"bundles", "bad prefix"}, {"bundles", "$(id)"},
		{"bundles", strings.Repeat("a", 500)}, {"bundles", "a@b@c"}, {"shells", "x"}, {"--help"},
	} {
		if got := complete(t, f.env(t), args...); len(got) != 0 {
			t.Errorf("%q printed %q", args, got)
		}
	}
	if n := f.hits.Load(); n != 0 {
		t.Errorf("%d requests for unusable arguments", n)
	}
}
