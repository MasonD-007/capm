package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MasonD-007/capm/backend/internal/store"
)

type statItem struct {
	Owner        string  `json:"owner"`
	Name         string  `json:"name"`
	Downloads30d *int64  `json:"downloads30d"`
	UpdatedAt    *string `json:"updatedAt"`
}

func (it statItem) key() string { return it.Owner + "/" + it.Name }

var day0 = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

// dlEnv is an API over a store whose clock the test controls.
type dlEnv struct {
	*quotaEnv
	now time.Time
}

func newDLEnv(t *testing.T) *dlEnv {
	t.Helper()
	q := quotaSetup(t, store.Limits{}, Config{})
	e := &dlEnv{quotaEnv: q, now: day0}
	q.st.SetClock(func() time.Time { return e.now })
	return e
}

// publishAt publishes with the store clock at unix second at.
func (e *dlEnv) publishAt(t *testing.T, owner, name, version string, at int64) {
	t.Helper()
	save := e.now
	e.now = time.Unix(at, 0)
	publishAs(t, e.env, owner, name, version, "desc of "+name)
	e.now = save
}

func (e *dlEnv) download(t *testing.T, owner, name, version string, times int) {
	t.Helper()
	for i := 0; i < times; i++ {
		if c, b := e.do(t, "GET", "/v1/bundles/"+owner+"/"+name+"/"+version+"/download", nil); c != 200 {
			t.Fatalf("download: %d %s", c, b)
		}
	}
}

func (e *dlEnv) stats(t *testing.T, query string) (int, []statItem, string) {
	t.Helper()
	c, b := e.do(t, "GET", "/v1/bundles"+query, nil)
	var out []statItem
	if c == 200 {
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("%s: %v: %s", query, err, b)
		}
	}
	return c, out, string(b)
}

func keys(items []statItem) string {
	var s []string
	for _, it := range items {
		s = append(s, it.key())
	}
	return strings.Join(s, ",")
}

func (e *dlEnv) meta(t *testing.T, owner, name, version string) map[string]any {
	t.Helper()
	c, b := e.do(t, "GET", "/v1/bundles/"+owner+"/"+name+"/"+version, nil)
	if c != 200 {
		t.Fatalf("metadata: %d %s", c, b)
	}
	return decode(t, b)
}

func TestDownloadCountsShowInMetadataVersionsAndList(t *testing.T) {
	e := newDLEnv(t)
	publishAs(t, e.env, "alice", "x", "1.0.0", "d")
	publishAs(t, e.env, "alice", "x", "1.1.0", "d")
	e.download(t, "alice", "x", "1.0.0", 3)
	e.download(t, "alice", "x", "1.1.0", 1)

	m := e.meta(t, "alice", "x", "1.0.0")
	if m["downloads"] != float64(3) || m["downloads30d"] != float64(3) {
		t.Fatalf("metadata = %v", m)
	}
	c, b := e.do(t, "GET", "/v1/bundles/alice/x", nil)
	var vs []struct {
		Version      string `json:"version"`
		Downloads    *int64 `json:"downloads"`
		Downloads30d *int64 `json:"downloads30d"`
	}
	if c != 200 || json.Unmarshal(b, &vs) != nil || len(vs) != 2 {
		t.Fatalf("versions: %d %s", c, b)
	}
	if *vs[0].Downloads != 3 || *vs[1].Downloads != 1 || *vs[0].Downloads30d != 3 {
		t.Fatalf("versions = %s", b)
	}
	_, items, body := e.stats(t, "")
	if len(items) != 1 || items[0].Downloads30d == nil || *items[0].Downloads30d != 4 {
		t.Fatalf("list = %s", body)
	}
}

func TestFreshVersionHasZeroNotMissingDownloads(t *testing.T) {
	e := newDLEnv(t)
	publishAs(t, e.env, "alice", "x", "1.0.0", "d")
	m := e.meta(t, "alice", "x", "1.0.0")
	if v, ok := m["downloads"]; !ok || v != float64(0) {
		t.Fatalf("downloads = %v, %v", v, ok)
	}
	if v, ok := m["downloads30d"]; !ok || v != float64(0) {
		t.Fatalf("downloads30d = %v, %v", v, ok)
	}
	_, items, body := e.stats(t, "")
	if items[0].Downloads30d == nil || *items[0].Downloads30d != 0 {
		t.Fatalf("list = %s", body)
	}
}

func TestFailedDownloadsDoNotCount(t *testing.T) {
	e := newDLEnv(t)
	publishAs(t, e.env, "alice", "x", "1.0.0", "d")
	publishAs(t, e.env, "alice", "x", "1.1.0", "d")
	e.download(t, "alice", "x", "1.0.0", 1)
	if c, _ := e.do(t, "GET", "/v1/bundles/alice/x/9.9.9/download", nil); c != 404 {
		t.Fatalf("unknown version: %d", c)
	}
	if c, _ := e.do(t, "GET", "/v1/bundles/nobody/x/1.0.0/download", nil); c != 404 {
		t.Fatalf("unknown owner: %d", c)
	}
	if _, err := e.st.RemoveVersion(99, "alice", "x", "1.1.0", "bad"); err != nil {
		t.Fatal(err)
	}
	if c, _ := e.do(t, "GET", "/v1/bundles/alice/x/1.1.0/download", nil); c != 410 {
		t.Fatalf("removed version: %d", c)
	}
	got, _ := e.st.VersionDownloads("alice", "x")
	if got["1.0.0"].Total != 1 || len(got) != 1 {
		t.Fatalf("counts = %+v", got)
	}
}

func TestHeadRequestsDoNotCount(t *testing.T) {
	e := newDLEnv(t)
	publishAs(t, e.env, "alice", "x", "1.0.0", "d")
	for _, method := range []string{"HEAD", "GET"} {
		req, _ := http.NewRequest(method, e.srv.URL+"/v1/bundles/alice/x/1.0.0/download", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("%s: %v %v", method, resp, err)
		}
		resp.Body.Close()
	}
	got, _ := e.st.VersionDownloads("alice", "x")
	if got["1.0.0"].Total != 1 {
		t.Fatalf("HEAD+GET counted %d, want 1", got["1.0.0"].Total)
	}
}

func TestCountFailureDoesNotFailTheDownload(t *testing.T) {
	e := newDLEnv(t)
	publishAs(t, e.env, "alice", "x", "1.0.0", "d")
	a := New(e.st, func(r *http.Request) (int64, string, bool) { return 0, "", false })
	a.countDownload = func(owner, name, version string) error { return errors.New("disk full") }
	srv := httptest.NewServer(a.Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v1/bundles/alice/x/1.0.0/download")
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("%v %v", resp, err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "application/gzip" {
		t.Fatalf("content-type %q", resp.Header.Get("Content-Type"))
	}
}

func TestConcurrentDownloadsCountExactly(t *testing.T) {
	e := newDLEnv(t)
	publishAs(t, e.env, "alice", "x", "1.0.0", "d")
	const workers, each = 10, 6
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				resp, err := http.Get(e.srv.URL + "/v1/bundles/alice/x/1.0.0/download")
				if err != nil {
					t.Error(err)
					return
				}
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	// The handler counts after writing, so allow the last increments to land.
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, _ := e.st.VersionDownloads("alice", "x")
		if got["1.0.0"].Total == workers*each {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("total = %d, want %d", got["1.0.0"].Total, workers*each)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestThirtyDayWindowMovesWithTheClock(t *testing.T) {
	e := newDLEnv(t)
	publishAs(t, e.env, "alice", "x", "1.0.0", "d")
	e.download(t, "alice", "x", "1.0.0", 2)
	e.now = day0.AddDate(0, 0, 29) // day 30 of the window: still in
	if m := e.meta(t, "alice", "x", "1.0.0"); m["downloads30d"] != float64(2) {
		t.Fatalf("day 29 later: %v", m)
	}
	e.now = day0.AddDate(0, 0, 30) // out of the window, still in all-time
	m := e.meta(t, "alice", "x", "1.0.0")
	if m["downloads30d"] != float64(0) || m["downloads"] != float64(2) {
		t.Fatalf("day 30 later: %v", m)
	}
}

func TestRemovedVersionsLeaveDisplayedTotals(t *testing.T) {
	e := newDLEnv(t)
	publishAs(t, e.env, "alice", "x", "1.0.0", "d")
	publishAs(t, e.env, "alice", "x", "1.1.0", "d")
	e.download(t, "alice", "x", "1.0.0", 2)
	e.download(t, "alice", "x", "1.1.0", 5)
	if _, err := e.st.RemoveVersion(99, "alice", "x", "1.1.0", "bad"); err != nil {
		t.Fatal(err)
	}
	_, items, body := e.stats(t, "")
	if *items[0].Downloads30d != 2 {
		t.Fatalf("list = %s", body)
	}
	_, b := e.do(t, "GET", "/v1/bundles/alice/x", nil)
	var vs []struct {
		Version   string `json:"version"`
		Removed   bool   `json:"removed"`
		Downloads int64  `json:"downloads"`
	}
	json.Unmarshal(b, &vs)
	if vs[0].Downloads != 2 || !vs[1].Removed || vs[1].Downloads != 0 {
		t.Fatalf("versions = %s", b)
	}
}

// Six bundles with distinct publish times and downloads.
//
//	name order:   alice/aaa, alice/bbb, bob/ccc, bob/ddd, carol/eee, dave/fff
//	recent order: carol/eee (600), bob/ddd (500) ... alice/aaa (100)
func sortEnv(t *testing.T) *dlEnv {
	e := newDLEnv(t)
	e.publishAt(t, "alice", "aaa", "1.0.0", 100)
	e.publishAt(t, "alice", "bbb", "1.0.0", 300)
	e.publishAt(t, "bob", "ccc", "1.0.0", 200)
	e.publishAt(t, "bob", "ddd", "1.0.0", 500)
	e.publishAt(t, "carol", "eee", "1.0.0", 600)
	e.publishAt(t, "dave", "fff", "1.0.0", 400)
	e.download(t, "bob", "ccc", "1.0.0", 5)
	e.download(t, "dave", "fff", "1.0.0", 3)
	e.download(t, "alice", "bbb", "1.0.0", 3) // ties with dave/fff
	e.download(t, "carol", "eee", "1.0.0", 1)
	return e
}

func TestListSortModes(t *testing.T) {
	e := sortEnv(t)
	for _, tc := range []struct{ query, want string }{
		{"", "alice/aaa,alice/bbb,bob/ccc,bob/ddd,carol/eee,dave/fff"},
		{"?sort=name", "alice/aaa,alice/bbb,bob/ccc,bob/ddd,carol/eee,dave/fff"},
		{"?sort=recent", "carol/eee,bob/ddd,dave/fff,alice/bbb,bob/ccc,alice/aaa"},
		{"?sort=downloads", "bob/ccc,alice/bbb,dave/fff,carol/eee,alice/aaa,bob/ddd"},
	} {
		c, items, body := e.stats(t, tc.query)
		if c != 200 || keys(items) != tc.want {
			t.Errorf("%q: %d %s\nwant %s", tc.query, c, keys(items), tc.want)
			_ = body
		}
	}
}

func TestListSortComposesWithOwnerQLimitOffset(t *testing.T) {
	e := sortEnv(t)
	for _, tc := range []struct{ query, want string }{
		{"?sort=recent&limit=2", "carol/eee,bob/ddd"},
		{"?sort=recent&limit=2&offset=2", "dave/fff,alice/bbb"},
		{"?sort=recent&limit=2&offset=4", "bob/ccc,alice/aaa"},
		{"?sort=recent&limit=2&offset=6", ""},
		{"?sort=downloads&limit=2&offset=1", "alice/bbb,dave/fff"},
		{"?sort=downloads&owner=bob", "bob/ccc,bob/ddd"},
		{"?sort=recent&owner=BOB", "bob/ddd,bob/ccc"},
		// q matches by owner, name or description; the order is the sort's,
		// over the full match set, before paging.
		{"?sort=downloads&q=bob", "bob/ccc,bob/ddd"},
		{"?sort=recent&q=desc%20of", "carol/eee,bob/ddd,dave/fff,alice/bbb,bob/ccc,alice/aaa"},
		{"?sort=downloads&q=desc%20of&limit=2&offset=1", "alice/bbb,dave/fff"},
		{"?sort=recent&q=desc%20of&limit=2&offset=5", "alice/aaa"},
		{"?sort=recent&q=nothing", ""},
		{"?sort=name&q=desc%20of&limit=2&offset=1", "alice/bbb,bob/ccc"},
	} {
		c, items, body := e.stats(t, tc.query)
		if c != 200 || keys(items) != tc.want {
			t.Errorf("%q: %d %s\nwant %s (%s)", tc.query, c, keys(items), tc.want, body)
		}
	}
}

func TestListUnknownSortIs400(t *testing.T) {
	e := sortEnv(t)
	for _, q := range []string{"?sort=bogus", "?sort=Recent", "?sort=downloads30d", "?sort=name,recent"} {
		if c, _, body := e.stats(t, q); c != 400 || !strings.Contains(body, "sort must be one of") {
			t.Errorf("%q: %d %s", q, c, body)
		}
	}
	// An empty value means "not given".
	if c, items, _ := e.stats(t, "?sort="); c != 200 || len(items) != 6 {
		t.Errorf("empty sort: %d", c)
	}
}

func TestListItemsCarryUpdatedAtAndDownloads30d(t *testing.T) {
	e := sortEnv(t)
	_, items, body := e.stats(t, "?sort=recent&limit=1")
	if len(items) != 1 || items[0].UpdatedAt == nil || *items[0].UpdatedAt != time.Unix(600, 0).UTC().Format(time.RFC3339) {
		t.Fatalf("item = %s", body)
	}
	if *items[0].Downloads30d != 1 {
		t.Fatalf("item = %s", body)
	}
}

func TestUpdatedAtOmittedWhenNoLiveVersionAndSortsLast(t *testing.T) {
	e := sortEnv(t)
	if _, err := e.st.RemoveBundle(99, "carol", "eee", "bad"); err != nil {
		t.Fatal(err)
	}
	c, b := e.do(t, "GET", "/v1/bundles?sort=recent", nil)
	if c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	var raw []map[string]any
	json.Unmarshal(b, &raw)
	last := raw[len(raw)-1]
	if last["name"] != "eee" {
		t.Fatalf("order = %s", b)
	}
	if _, has := last["updatedAt"]; has {
		t.Fatalf("updatedAt present with no live version: %v", last)
	}
	if last["downloads30d"] != float64(0) {
		t.Fatalf("removed bundle's downloads30d = %v", last["downloads30d"])
	}
}

func TestBannedOwnersStayHiddenWithSort(t *testing.T) {
	e := sortEnv(t)
	id, err := e.st.UserIDByLogin("bob")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.BanUser(99, id, "spam"); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"name", "recent", "downloads"} {
		_, items, _ := e.stats(t, "?sort="+s)
		if strings.Contains(keys(items), "bob/") || len(items) != 4 {
			t.Errorf("sort=%s: %s", s, keys(items))
		}
	}
}

// Counts must never change what a search matches or the default order.
func TestDownloadsDoNotAffectDefaultOrderOrSearch(t *testing.T) {
	e := sortEnv(t)
	_, before, _ := e.stats(t, "?q=desc%20of")
	e.download(t, "bob", "ddd", "1.0.0", 50)
	_, after, _ := e.stats(t, "?q=desc%20of")
	if keys(before) != keys(after) || keys(after) != "alice/aaa,alice/bbb,bob/ccc,bob/ddd,carol/eee,dave/fff" {
		t.Fatalf("before %s after %s", keys(before), keys(after))
	}
}

func TestPagingWalksTheSortedSetExactlyOnce(t *testing.T) {
	e := sortEnv(t)
	for _, s := range []string{"name", "recent", "downloads"} {
		_, all, _ := e.stats(t, "?sort="+s)
		var walked []statItem
		for off := 0; off < 6; off += 2 {
			_, page, _ := e.stats(t, "?sort="+s+"&limit=2&offset="+strconv.Itoa(off))
			walked = append(walked, page...)
		}
		if keys(walked) != keys(all) {
			t.Errorf("sort=%s: paged %s, full %s", s, keys(walked), keys(all))
		}
	}
}
