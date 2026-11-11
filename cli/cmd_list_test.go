package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/MasonD-007/capm/cli/internal/client"
)

// listServer serves GET /v1/bundles from fixed pages and records each query.
type listServer struct {
	srv     *httptest.Server
	mu      sync.Mutex
	queries []string
	auth    []string
	status  int // non-zero: fail every request with this status
	all     func(offset, limit int) []client.BundleInfo
}

func newListServer(t *testing.T, all func(offset, limit int) []client.BundleInfo) *listServer {
	t.Helper()
	ls := &listServer{all: all}
	ls.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ls.mu.Lock()
		ls.queries = append(ls.queries, r.URL.RawQuery)
		ls.auth = append(ls.auth, r.Header.Get("Authorization"))
		ls.mu.Unlock()
		if ls.status != 0 {
			w.WriteHeader(ls.status)
			fmt.Fprint(w, `{"error":"boom"}`)
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		json.NewEncoder(w).Encode(ls.all(offset, limit))
	}))
	t.Cleanup(ls.srv.Close)
	return ls
}

func fixed(bs ...client.BundleInfo) func(int, int) []client.BundleInfo {
	return func(offset, limit int) []client.BundleInfo {
		if offset >= len(bs) {
			return []client.BundleInfo{}
		}
		return bs[offset:min(offset+limit, len(bs))]
	}
}

func (ls *listServer) run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := runEnv(args, &out, &errb, env{registry: ls.srv.URL})
	return code, out.String(), errb.String()
}

func TestSearchAndListUsage(t *testing.T) {
	ls := newListServer(t, fixed())
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"search"}, "usage: capm search <text>"},
		{[]string{"search", "a", "b"}, "usage: capm search <text>"},
		{[]string{"list", "a", "b"}, "usage: capm list [owner]"},
	} {
		code, out, errs := ls.run(tc.args...)
		if code != 2 || out != "" || !strings.Contains(errs, tc.want) {
			t.Errorf("%v: code %d out %q err %q", tc.args, code, out, errs)
		}
	}
	if len(ls.queries) != 0 {
		t.Errorf("usage errors must not hit the registry: %v", ls.queries)
	}
}

func TestSearchSendsQueryWithoutCredentials(t *testing.T) {
	ls := newListServer(t, fixed(client.BundleInfo{Owner: "alice", Name: "pr-reviewer", Latest: "1.0.0", Description: "Reviews"}))
	code, out, errs := ls.run("search", "pr rev&")
	if code != 0 || errs != "" {
		t.Fatalf("code %d err %q", code, errs)
	}
	if want := "limit=200&offset=0&q=pr+rev%26"; len(ls.queries) != 1 || ls.queries[0] != want {
		t.Errorf("queries %v, want %q", ls.queries, want)
	}
	if ls.auth[0] != "" {
		t.Errorf("sent credentials: %q", ls.auth[0])
	}
	if want := "alice/pr-reviewer  1.0.0  Reviews\n"; out != want {
		t.Errorf("out %q, want %q", out, want)
	}
}

func TestListOwnerFilter(t *testing.T) {
	ls := newListServer(t, fixed(client.BundleInfo{Owner: "alice", Name: "x", Latest: "1.0.0"}))
	if code, _, errs := ls.run("list", "alice"); code != 0 {
		t.Fatalf("code %d %s", code, errs)
	}
	if want := "limit=200&offset=0&owner=alice"; ls.queries[0] != want {
		t.Errorf("query %q, want %q", ls.queries[0], want)
	}
	ls.queries = nil
	ls.run("list")
	if want := "limit=200&offset=0"; ls.queries[0] != want {
		t.Errorf("query %q, want %q", ls.queries[0], want)
	}
}

func TestListFormatting(t *testing.T) {
	long := strings.Repeat("é", 100)
	ls := newListServer(t, fixed(
		client.BundleInfo{Owner: "alice", Name: "a", Latest: "1.0.0", Description: "first line\nsecond line"},
		client.BundleInfo{Owner: "bob", Name: "much-longer-name", Latest: "", Description: ""},
		client.BundleInfo{Owner: "carol", Name: "c", Latest: "2.0.0-rc.1", Description: long},
		client.BundleInfo{Owner: "dave", Name: "d", Latest: "1.0.0", Description: strings.Repeat("x", 80)},
	))
	code, out, errs := ls.run("list")
	if code != 0 || errs != "" {
		t.Fatalf("code %d err %q", code, errs)
	}
	want := "alice/a               1.0.0       first line\n" +
		"bob/much-longer-name  -           \n" +
		"carol/c               2.0.0-rc.1  " + strings.Repeat("é", 79) + "…\n" +
		"dave/d                1.0.0       " + strings.Repeat("x", 80) + "\n"
	// tabwriter pads trailing empty cells only when followed by a tab, so
	// compare per line with trailing spaces trimmed.
	got := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for i, w := range strings.Split(strings.TrimRight(want, "\n"), "\n") {
		if i >= len(got) || strings.TrimRight(got[i], " ") != strings.TrimRight(w, " ") {
			t.Errorf("line %d:\n got %q\nwant %q", i, got[min(i, len(got)-1)], w)
		}
	}
}

func TestListNoResults(t *testing.T) {
	ls := newListServer(t, fixed())
	code, out, errs := ls.run("search", "zzz")
	if code != 0 || out != "" || errs != "no bundles found\n" {
		t.Errorf("code %d out %q err %q", code, out, errs)
	}
}

func TestListSanitisesRegistryStrings(t *testing.T) {
	evil := "ok\x1b[31mred\u202eevil\u0085end"
	ls := newListServer(t, fixed(client.BundleInfo{
		Owner: "al\x1b]0;x\x07ice", Name: "n\u202eame", Latest: "1.0.0\x1b[2J", Description: evil,
	}))
	code, out, errs := ls.run("list")
	if code != 0 {
		t.Fatalf("code %d %s", code, errs)
	}
	for _, bad := range []string{"\x1b", "\u202e", "\u0085", "\x07"} {
		if strings.Contains(out, bad) || strings.Contains(errs, bad) {
			t.Errorf("%q reached the terminal: %q", bad, out)
		}
	}
	if !strings.Contains(out, "ok[31mredevilend") {
		t.Errorf("sanitised description missing: %q", out)
	}
}

func TestListPagesUntilShort(t *testing.T) {
	all := func(offset, limit int) []client.BundleInfo {
		var out []client.BundleInfo
		for i := offset; i < min(offset+limit, 450); i++ {
			out = append(out, client.BundleInfo{Owner: "o", Name: fmt.Sprintf("b%03d", i), Latest: "1.0.0"})
		}
		return out
	}
	ls := newListServer(t, all)
	code, out, errs := ls.run("list")
	if code != 0 || errs != "" {
		t.Fatalf("code %d err %q", code, errs)
	}
	if n := strings.Count(out, "\n"); n != 450 {
		t.Errorf("%d lines, want 450", n)
	}
	want := []string{"limit=200&offset=0", "limit=200&offset=200", "limit=200&offset=400"}
	if strings.Join(ls.queries, "|") != strings.Join(want, "|") {
		t.Errorf("queries %v, want %v", ls.queries, want)
	}
}

func TestListCapsAt2000AndNotes(t *testing.T) {
	endless := func(offset, limit int) []client.BundleInfo {
		out := make([]client.BundleInfo, limit)
		for i := range out {
			out[i] = client.BundleInfo{Owner: "o", Name: fmt.Sprintf("b%05d", offset+i), Latest: "1.0.0"}
		}
		return out
	}
	ls := newListServer(t, endless)
	code, out, errs := ls.run("search", "b")
	if code != 0 {
		t.Fatalf("code %d %s", code, errs)
	}
	if n := strings.Count(out, "\n"); n != 2000 {
		t.Errorf("%d lines, want 2000", n)
	}
	if len(ls.queries) != 10 {
		t.Errorf("%d requests, want 10", len(ls.queries))
	}
	if !strings.Contains(errs, "truncated") || !strings.Contains(errs, "capm search") {
		t.Errorf("stderr %q lacks truncation note", errs)
	}
}

func TestListNoTruncationNoteUnderCap(t *testing.T) {
	ls := newListServer(t, fixed(client.BundleInfo{Owner: "o", Name: "x", Latest: "1.0.0"}))
	if _, _, errs := ls.run("list"); strings.Contains(errs, "truncated") {
		t.Errorf("unexpected note: %q", errs)
	}
}

func TestListErrors(t *testing.T) {
	ls := newListServer(t, fixed())
	ls.status = 500
	for _, cmd := range []string{"search", "list"} {
		args := []string{cmd}
		if cmd == "search" {
			args = append(args, "x")
		}
		code, out, errs := ls.run(args...)
		if code != 1 || out != "" || !strings.HasPrefix(errs, "capm "+cmd+": ") || !strings.Contains(errs, "boom") {
			t.Errorf("%s: code %d out %q err %q", cmd, code, out, errs)
		}
	}
}

func TestVersionCommand(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })
	var out, errb bytes.Buffer
	if code := runEnv([]string{"version"}, &out, &errb, env{}); code != 0 || out.String() != "capm dev\n" || errb.String() != "" {
		t.Errorf("default: code %d out %q err %q", code, out.String(), errb.String())
	}
	version = "abc1234"
	out.Reset()
	if code := runEnv([]string{"version"}, &out, &errb, env{}); code != 0 || out.String() != "capm abc1234\n" {
		t.Errorf("set: code %d out %q", code, out.String())
	}
}

func TestUsageListsNewCommands(t *testing.T) {
	for _, c := range []string{"search", "list", "version"} {
		if !strings.Contains(usage, "\n  "+c) {
			t.Errorf("usage lacks %s", c)
		}
	}
}
