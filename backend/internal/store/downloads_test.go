package store

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

func dayOf(t time.Time) int64 { return t.Unix() / 86400 }

func dlStore(t *testing.T) *Store {
	t.Helper()
	s := openStore(t)
	s.SetClock(func() time.Time { return t0 })
	return s
}

// addDL inserts a daily row directly (history that predates the test).
func addDL(t *testing.T, s *Store, owner int64, name, version string, day, n int64) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT INTO downloads(owner_id,name,version,day,count) VALUES(?,?,?,?,?)
		ON CONFLICT(owner_id,name,version,day) DO UPDATE SET count = count + excluded.count`, owner, name, version, day, n); err != nil {
		t.Fatal(err)
	}
}

func total(t *testing.T, s *Store, owner, name, version string) DownloadCounts {
	t.Helper()
	m, err := s.VersionDownloads(owner, name)
	if err != nil {
		t.Fatal(err)
	}
	return m[version]
}

func TestCountDownloadIncrementsOneRowPerDay(t *testing.T) {
	s := dlStore(t)
	publish(t, s, 1, "alice", "x", "1.0.0")
	for i := 0; i < 3; i++ {
		if err := s.CountDownload("alice", "x", "1.0.0"); err != nil {
			t.Fatal(err)
		}
	}
	rows := dumpRows(t, s.db, `SELECT owner_id,name,version,day,count FROM downloads`)
	want := [][]any{{int64(1), "x", "1.0.0", dayOf(t0), int64(3)}}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %v, want %v", rows, want)
	}
	// Login matching is case-insensitive like the rest of the API.
	if err := s.CountDownload("ALICE", "x", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if c := total(t, s, "alice", "x", "1.0.0"); c.Total != 4 {
		t.Fatalf("total = %d", c.Total)
	}
}

func TestCountDownloadUnknownVersionIsNotFoundAndStoresNothing(t *testing.T) {
	s := dlStore(t)
	publish(t, s, 1, "alice", "x", "1.0.0")
	for _, c := range [][3]string{{"alice", "x", "9.9.9"}, {"alice", "nope", "1.0.0"}, {"zed", "x", "1.0.0"}} {
		if err := s.CountDownload(c[0], c[1], c[2]); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%v: err = %v", c, err)
		}
	}
	if n := dumpRows(t, s.db, `SELECT count(*) FROM downloads`); n[0][0] != int64(0) {
		t.Fatalf("rows stored for unknown versions: %v", n)
	}
}

func TestCountDownloadCrossesUTCDayBoundary(t *testing.T) {
	s := openStore(t)
	publish(t, s, 1, "alice", "x", "1.0.0")
	now := time.Date(2026, 11, 12, 23, 59, 59, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	s.CountDownload("alice", "x", "1.0.0")
	now = now.Add(time.Second) // 00:00:00 the next UTC day
	s.CountDownload("alice", "x", "1.0.0")
	s.CountDownload("alice", "x", "1.0.0")
	rows := dumpRows(t, s.db, `SELECT day,count FROM downloads ORDER BY day`)
	d := dayOf(now)
	if !reflect.DeepEqual(rows, [][]any{{d - 1, int64(1)}, {d, int64(2)}}) {
		t.Fatalf("rows = %v", rows)
	}
}

func TestCountDownloadConcurrentIsExact(t *testing.T) {
	s := dlStore(t)
	publish(t, s, 1, "alice", "x", "1.0.0")
	const workers, each = 16, 25
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				if err := s.CountDownload("alice", "x", "1.0.0"); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	if c := total(t, s, "alice", "x", "1.0.0"); c.Total != workers*each {
		t.Fatalf("total = %d, want %d", c.Total, workers*each)
	}
}

func TestThirtyDayWindowIncludesTodayAndExcludesDay30(t *testing.T) {
	s := dlStore(t)
	publish(t, s, 1, "alice", "x", "1.0.0")
	today := dayOf(t0)
	addDL(t, s, 1, "x", "1.0.0", today, 1)      // in
	addDL(t, s, 1, "x", "1.0.0", today-29, 10)  // in (30th day)
	addDL(t, s, 1, "x", "1.0.0", today-30, 100) // out
	addDL(t, s, 1, "x", "1.0.0", dayBeforeWindow, 1000)
	c := total(t, s, "alice", "x", "1.0.0")
	if c.Last30d != 11 || c.Total != 1111 {
		t.Fatalf("counts = %+v, want 30d 11 total 1111", c)
	}
	st, err := s.ListStats("", SortName, -1, 0)
	if err != nil || len(st) != 1 || st[0].Downloads30d != 11 {
		t.Fatalf("stats = %+v, %v", st, err)
	}
}

func TestRemovedVersionsKeepRowsButLeaveTotals(t *testing.T) {
	s := dlStore(t)
	publish(t, s, 1, "alice", "x", "1.0.0")
	publish(t, s, 1, "alice", "x", "1.1.0")
	addDL(t, s, 1, "x", "1.0.0", dayOf(t0), 5)
	addDL(t, s, 1, "x", "1.1.0", dayOf(t0), 7)
	if _, err := s.RemoveVersion(99, "alice", "x", "1.0.0", "bad"); err != nil {
		t.Fatal(err)
	}
	m, _ := s.VersionDownloads("alice", "x")
	if _, ok := m["1.0.0"]; ok || m["1.1.0"].Total != 7 {
		t.Fatalf("per-version = %+v", m)
	}
	st, _ := s.ListStats("", SortName, -1, 0)
	if st[0].Downloads30d != 7 {
		t.Fatalf("bundle 30d = %d, want 7 (removed excluded)", st[0].Downloads30d)
	}
	if n := dumpRows(t, s.db, `SELECT sum(count) FROM downloads`); n[0][0] != int64(12) {
		t.Fatalf("history was deleted: %v", n)
	}
}

func TestBannedOwnersAreHiddenFromStatsAndDownloads(t *testing.T) {
	s := dlStore(t)
	publish(t, s, 1, "alice", "x", "1.0.0")
	publish(t, s, 2, "bob", "y", "1.0.0")
	addDL(t, s, 1, "x", "1.0.0", dayOf(t0), 5)
	if err := s.BanUser(99, 1, "spam"); err != nil {
		t.Fatal(err)
	}
	st, _ := s.ListStats("", SortDownloads, -1, 0)
	if len(st) != 1 || st[0].OwnerLogin != "bob" {
		t.Fatalf("stats = %+v", st)
	}
	if _, err := s.VersionDownloads("alice", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("banned VersionDownloads err = %v", err)
	}
	if err := s.CountDownload("alice", "x", "1.0.0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("banned CountDownload err = %v", err)
	}
}

func TestListStatsSortsAndPagesStably(t *testing.T) {
	s := openStore(t)
	// created_at: a/old 100, b/mid 200, c/new 300, d/tie 300 (same second as c).
	for i, p := range []struct {
		id          int64
		login, name string
		at          int64
	}{{1, "alice", "old", 100}, {2, "bob", "mid", 200}, {3, "carol", "new", 300}, {4, "dave", "tie", 300}} {
		_ = i
		at := p.at
		s.SetClock(func() time.Time { return time.Unix(at, 0) })
		publish(t, s, p.id, p.login, p.name, "1.0.0")
	}
	s.SetClock(func() time.Time { return t0 })
	today := dayOf(t0)
	addDL(t, s, 1, "old", "1.0.0", today, 9)
	addDL(t, s, 2, "mid", "1.0.0", today, 9) // ties with old
	addDL(t, s, 3, "new", "1.0.0", today, 1)

	order := func(sort string, limit, offset int) string {
		st, err := s.ListStats("", sort, limit, offset)
		if err != nil {
			t.Fatal(err)
		}
		out := ""
		for _, b := range st {
			out += b.OwnerLogin + "/" + b.Name + ","
		}
		return out
	}
	if got := order(SortName, -1, 0); got != "alice/old,bob/mid,carol/new,dave/tie," {
		t.Fatalf("name: %s", got)
	}
	if got := order(SortRecent, -1, 0); got != "carol/new,dave/tie,bob/mid,alice/old," {
		t.Fatalf("recent: %s", got)
	}
	if got := order(SortDownloads, -1, 0); got != "alice/old,bob/mid,carol/new,dave/tie," {
		t.Fatalf("downloads: %s", got)
	}
	// Pages are slices of the one full order.
	if got := order(SortRecent, 2, 1); got != "dave/tie,bob/mid," {
		t.Fatalf("recent page: %s", got)
	}
	if got := order(SortDownloads, 1, 3); got != "dave/tie," {
		t.Fatalf("downloads page: %s", got)
	}
	st, _ := s.ListStats("bob", SortRecent, -1, 0)
	if len(st) != 1 || st[0].UpdatedAt.Unix() != 200 || st[0].Downloads30d != 9 {
		t.Fatalf("owner filter/fields: %+v", st)
	}
}

func TestUpdatedAtIgnoresRemovedVersionsAndIsZeroWhenNone(t *testing.T) {
	s := openStore(t)
	s.SetClock(func() time.Time { return time.Unix(100, 0) })
	publish(t, s, 1, "alice", "x", "1.0.0")
	s.SetClock(func() time.Time { return time.Unix(200, 0) })
	publish(t, s, 1, "alice", "x", "1.1.0")
	s.SetClock(func() time.Time { return t0 })
	s.RemoveVersion(99, "alice", "x", "1.1.0", "bad")
	st, _ := s.ListStats("", SortRecent, -1, 0)
	if st[0].UpdatedAt.Unix() != 100 {
		t.Fatalf("updatedAt = %v, want the non-removed version's 100", st[0].UpdatedAt)
	}
	s.RemoveVersion(99, "alice", "x", "1.0.0", "bad")
	st, _ = s.ListStats("", SortRecent, -1, 0)
	if len(st) != 1 || !st[0].UpdatedAt.IsZero() {
		t.Fatalf("all removed: %+v", st)
	}
}

func TestPublishUsesTheInjectedClock(t *testing.T) {
	s := dlStore(t)
	publish(t, s, 1, "alice", "x", "1.0.0")
	vs, _ := s.Versions("alice", "x")
	if !vs[0].CreatedAt.Equal(t0) {
		t.Fatalf("created_at = %v, want %v", vs[0].CreatedAt, t0)
	}
}

func TestRollupFoldsOldDaysIntoSentinelRow(t *testing.T) {
	s := dlStore(t)
	publish(t, s, 1, "alice", "x", "1.0.0")
	publish(t, s, 1, "alice", "x", "1.1.0")
	today := dayOf(t0)
	cutoff := today - retentionDays // days < cutoff are rolled up
	addDL(t, s, 1, "x", "1.0.0", cutoff-1, 3)
	addDL(t, s, 1, "x", "1.0.0", cutoff-50, 4)
	addDL(t, s, 1, "x", "1.0.0", dayBeforeWindow, 100) // an earlier rollup
	addDL(t, s, 1, "x", "1.0.0", cutoff, 5)            // exactly on the boundary: kept
	addDL(t, s, 1, "x", "1.0.0", today, 1)
	addDL(t, s, 1, "x", "1.1.0", cutoff-2, 8) // only old rows
	before := total(t, s, "alice", "x", "1.0.0")
	if err := s.rollupDownloads(); err != nil {
		t.Fatal(err)
	}
	rows := dumpRows(t, s.db, `SELECT version,day,count FROM downloads ORDER BY version, day`)
	want := [][]any{
		{"1.0.0", int64(dayBeforeWindow), int64(107)},
		{"1.0.0", cutoff, int64(5)},
		{"1.0.0", today, int64(1)},
		{"1.1.0", int64(dayBeforeWindow), int64(8)},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows after rollup = %v\nwant %v", rows, want)
	}
	if after := total(t, s, "alice", "x", "1.0.0"); after != before {
		t.Fatalf("totals changed: %+v -> %+v", before, after)
	}
	// Idempotent.
	if err := s.rollupDownloads(); err != nil {
		t.Fatal(err)
	}
	if again := dumpRows(t, s.db, `SELECT version,day,count FROM downloads ORDER BY version, day`); !reflect.DeepEqual(again, want) {
		t.Fatalf("second run changed rows: %v", again)
	}
}

func TestOpenRunsRollup(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	publish(t, s, 1, "alice", "x", "1.0.0")
	old := dayOf(time.Now()) - retentionDays - 10
	addDL(t, s, 1, "x", "1.0.0", old, 6)
	addDL(t, s, 1, "x", "1.0.0", old-1, 6)
	s.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	rows := dumpRows(t, s2.db, `SELECT day,count FROM downloads`)
	if !reflect.DeepEqual(rows, [][]any{{int64(dayBeforeWindow), int64(12)}}) {
		t.Fatalf("rows = %v", rows)
	}
}

// The 30-day aggregation must be answered from the downloads_day index, not a
// scan of the whole table.
func TestThirtyDayAggregationUsesDayIndex(t *testing.T) {
	s := dlStore(t)
	rows, err := s.db.Query(`EXPLAIN QUERY PLAN `+statsQuery(SortName), dayOf(t0)-29, "", "", -1, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		rows.Scan(&id, &parent, &unused, &detail)
		plan += detail + "\n"
	}
	if !contains(plan, "downloads_day") {
		t.Fatalf("plan does not use downloads_day:\n%s", plan)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
