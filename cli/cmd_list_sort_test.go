package main

import (
	"strings"
	"testing"

	"github.com/MasonD-007/capm/cli/internal/client"
)

func n64(n int64) *int64 { return &n }

func sortedFixture() []client.BundleInfo {
	return []client.BundleInfo{
		{Owner: "alice", Name: "a", Latest: "1.0.0", Description: "first", Downloads30d: n64(12), UpdatedAt: "2026-11-10T08:00:00Z"},
		{Owner: "bob", Name: "b", Latest: "2.0.0", Description: "second", Downloads30d: n64(0)},
	}
}

func TestListSortFlagPositionsAndQuery(t *testing.T) {
	for _, tc := range []struct {
		args  []string
		query string
	}{
		{[]string{"list", "--sort", "downloads"}, "limit=200&offset=0&sort=downloads"},
		{[]string{"list", "--sort=recent"}, "limit=200&offset=0&sort=recent"},
		{[]string{"list", "--sort", "recent", "alice"}, "limit=200&offset=0&owner=alice&sort=recent"},
		{[]string{"list", "alice", "--sort", "recent"}, "limit=200&offset=0&owner=alice&sort=recent"},
		{[]string{"search", "--sort=downloads", "foo"}, "limit=200&offset=0&q=foo&sort=downloads"},
		{[]string{"search", "foo", "--sort", "downloads"}, "limit=200&offset=0&q=foo&sort=downloads"},
	} {
		ls := newListServer(t, fixed(sortedFixture()...))
		code, _, errs := ls.run(tc.args...)
		if code != 0 || errs != "" {
			t.Errorf("%v: code %d err %q", tc.args, code, errs)
			continue
		}
		if len(ls.queries) != 1 || ls.queries[0] != tc.query {
			t.Errorf("%v: queries %v, want %q", tc.args, ls.queries, tc.query)
		}
	}
}

func TestListSortDownloadsAddsIntegerColumn(t *testing.T) {
	ls := newListServer(t, fixed(sortedFixture()...))
	code, out, errs := ls.run("list", "--sort", "downloads")
	if code != 0 || errs != "" {
		t.Fatalf("code %d err %q", code, errs)
	}
	want := "alice/a  1.0.0  12  first\nbob/b    2.0.0  0   second\n"
	if out != want {
		t.Errorf("out %q, want %q", out, want)
	}
}

func TestListSortRecentAddsDateColumn(t *testing.T) {
	ls := newListServer(t, fixed(sortedFixture()...))
	code, out, errs := ls.run("search", "x", "--sort", "recent")
	if code != 0 || errs != "" {
		t.Fatalf("code %d err %q", code, errs)
	}
	// bob has no updatedAt (nothing installable to date): "-".
	want := "alice/a  1.0.0  2026-11-10  first\nbob/b    2.0.0  -           second\n"
	if out != want {
		t.Errorf("out %q, want %q", out, want)
	}
}

func TestListSortColumnComesBeforeRiskMarker(t *testing.T) {
	b := sortedFixture()
	b[0].Risk = "high"
	ls := newListServer(t, fixed(b...))
	_, out, _ := ls.run("list", "--sort", "downloads")
	if !strings.HasPrefix(out, "alice/a  1.0.0  12  !!  first\n") {
		t.Errorf("out %q", out)
	}
}

func TestListSortNameIsTheDefaultOutput(t *testing.T) {
	plain := newListServer(t, fixed(sortedFixture()...))
	_, want, _ := plain.run("list")
	ls := newListServer(t, fixed(sortedFixture()...))
	code, out, errs := ls.run("list", "--sort", "name")
	if code != 0 || errs != "" || out != want {
		t.Errorf("code %d out %q err %q, want %q", code, out, errs, want)
	}
	if strings.Contains(ls.queries[0], "sort=") {
		t.Errorf("sort=name should not be sent: %q", ls.queries[0])
	}
	// And a registry that sends the new fields still gets the plain table
	// when no --sort is given.
	if strings.Contains(want, "12") || strings.Contains(want, "2026") {
		t.Errorf("default output grew a column: %q", want)
	}
}

func TestListSortUsageErrors(t *testing.T) {
	for _, args := range [][]string{
		{"list", "--sort", "newest"},
		{"list", "--sort="},
		{"list", "--sort"},
		{"search", "foo", "--sort", "Recent"},
		{"search", "--sort=bogus", "foo"},
		{"list", "--sort", "recent", "--sort", "downloads", "a"}, // repeated
		{"list", "a", "b", "--sort", "recent"},
		{"search", "--sort", "recent"},
	} {
		ls := newListServer(t, fixed(sortedFixture()...))
		code, out, errs := ls.run(args...)
		if code != 2 || out != "" || !strings.Contains(errs, "usage: capm") {
			t.Errorf("%v: code %d out %q err %q", args, code, out, errs)
		}
		if len(ls.queries) != 0 {
			t.Errorf("%v: usage error hit the registry: %v", args, ls.queries)
		}
	}
}

func TestListSortAgainstOlderServerNotesOnceAndShowsPlainTable(t *testing.T) {
	old := []client.BundleInfo{
		{Owner: "alice", Name: "a", Latest: "1.0.0", Description: "first"},
		{Owner: "bob", Name: "b", Latest: "2.0.0", Description: "second"},
	}
	for _, sort := range []string{"recent", "downloads"} {
		ls := newListServer(t, fixed(old...))
		code, out, errs := ls.run("list", "--sort", sort)
		if code != 0 {
			t.Fatalf("code %d", code)
		}
		if want := "alice/a  1.0.0  first\nbob/b    2.0.0  second\n"; out != want {
			t.Errorf("%s: out %q, want %q", sort, out, want)
		}
		if strings.Count(errs, "\n") != 1 || !strings.Contains(errs, "does not support sorting") {
			t.Errorf("%s: stderr %q", sort, errs)
		}
	}
}

func TestListSortOlderServerNoteIsOnceAcrossPages(t *testing.T) {
	all := func(offset, limit int) []client.BundleInfo {
		var out []client.BundleInfo
		for i := offset; i < min(offset+limit, 450); i++ {
			out = append(out, client.BundleInfo{Owner: "o", Name: "b", Latest: "1.0.0"})
		}
		return out
	}
	ls := newListServer(t, all)
	_, out, errs := ls.run("list", "--sort", "downloads")
	if strings.Count(out, "\n") != 450 || strings.Count(errs, "does not support sorting") != 1 {
		t.Errorf("lines %d, stderr %q", strings.Count(out, "\n"), errs)
	}
}

func TestListSortEmptyResultHasNoNote(t *testing.T) {
	ls := newListServer(t, fixed())
	code, out, errs := ls.run("list", "--sort", "recent")
	if code != 0 || out != "" || errs != "no bundles found\n" {
		t.Errorf("code %d out %q err %q", code, out, errs)
	}
}

func TestListSortBadServerDatesAndCountsAreHarmless(t *testing.T) {
	b := []client.BundleInfo{
		{Owner: "a", Name: "x", Latest: "1.0.0", Downloads30d: n64(-5), UpdatedAt: "2026-11-10\x1b[2J"},
		{Owner: "b", Name: "y", Latest: "1.0.0", Downloads30d: n64(1), UpdatedAt: "not a date"},
	}
	ls := newListServer(t, fixed(b...))
	_, out, _ := ls.run("list", "--sort", "recent")
	if strings.Contains(out, "\x1b") || strings.Contains(out, "not a date") {
		t.Errorf("untrusted date echoed: %q", out)
	}
	ls = newListServer(t, fixed(b...))
	_, out, _ = ls.run("list", "--sort", "downloads")
	if strings.Contains(out, "-5") {
		t.Errorf("negative count echoed: %q", out)
	}
}
