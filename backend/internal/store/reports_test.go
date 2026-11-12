package store

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func reportStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	s := openStore(t)
	now := time.Unix(1_800_000_000, 0)
	s.SetClock(func() time.Time { return now })
	publish(t, s, 1, "alice", "x", "1.0.0")
	publish(t, s, 1, "alice", "x", "1.1.0")
	return s, &now
}

func rin(key byte) ReportInput {
	return ReportInput{OwnerLogin: "alice", Name: "x", Version: "1.0.0", Reason: "malware", Details: "bad", ReporterKey: []byte{key}}
}

func openCount(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT count(*) FROM reports WHERE resolved_at IS NULL`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAddReportStoresAndResolvesCanonicalOwner(t *testing.T) {
	s, _ := reportStore(t)
	in := rin(1)
	in.OwnerLogin = "ALICE" // logins are case-insensitive, like every other route
	in.ReporterUserID = 7
	res, err := s.AddReport(in)
	if err != nil || res.Outcome != ReportStored || res.ID == 0 || res.OwnerLogin != "alice" {
		t.Fatalf("%+v %v", res, err)
	}
	got, err := s.GetReport(res.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.OwnerLogin != "alice" || got.Name != "x" || got.Version != "1.0.0" || got.Reason != "malware" ||
		got.Details != "bad" || got.ReporterID != 7 || got.Resolved() || got.BundleState != "live" {
		t.Fatalf("%+v", got)
	}
}

func TestAddReportRejectsUnknownBundleVersionAndBannedOwner(t *testing.T) {
	s, _ := reportStore(t)
	for name, mod := range map[string]func(*ReportInput){
		"owner":  func(i *ReportInput) { i.OwnerLogin = "nobody" },
		"bundle": func(i *ReportInput) { i.Name = "nope" },
	} {
		in := rin(1)
		mod(&in)
		if _, err := s.AddReport(in); !errors.Is(err, ErrNotFound) {
			t.Errorf("%s: err = %v, want ErrNotFound", name, err)
		}
	}
	in := rin(1)
	in.Version = "9.9.9"
	if _, err := s.AddReport(in); !errors.Is(err, ErrUnknownVersion) {
		t.Errorf("version: err = %v", err)
	}
	in.Version = "" // whole bundle is allowed
	if res, err := s.AddReport(in); err != nil || res.Outcome != ReportStored {
		t.Errorf("empty version: %+v %v", res, err)
	}
	if err := s.BanUser(99, 1, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddReport(rin(2)); !errors.Is(err, ErrNotFound) {
		t.Errorf("banned owner: err = %v", err)
	}
	if n := openCount(t, s); n != 1 {
		t.Errorf("%d reports stored, want 1", n)
	}
}

func TestAddReportAcceptedForYankedAndRemovedVersions(t *testing.T) {
	s, _ := reportStore(t)
	if err := s.SetYanked(1, "x", "1.0.0", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoveVersion(99, "alice", "x", "1.1.0", "spam"); err != nil {
		t.Fatal(err)
	}
	for i, v := range []string{"1.0.0", "1.1.0"} {
		in := rin(byte(i))
		in.Version = v
		if res, err := s.AddReport(in); err != nil || res.Outcome != ReportStored {
			t.Fatalf("%s: %+v %v", v, res, err)
		}
	}
}

func TestAddReportDeduplicatesWithin24Hours(t *testing.T) {
	s, now := reportStore(t)
	first, _ := s.AddReport(rin(1))
	*now = now.Add(23 * time.Hour)
	again, err := s.AddReport(rin(1))
	if err != nil || again.Outcome != ReportDuplicate || again.ID != first.ID {
		t.Fatalf("%+v %v (first %+v)", again, err, first)
	}
	if n := openCount(t, s); n != 1 {
		t.Fatalf("%d rows", n)
	}
	// Each part of the key matters.
	for name, mod := range map[string]func(*ReportInput){
		"reporter": func(i *ReportInput) { i.ReporterKey = []byte{2} },
		"reason":   func(i *ReportInput) { i.Reason = "other" },
		"version":  func(i *ReportInput) { i.Version = "1.1.0" },
	} {
		in := rin(1)
		mod(&in)
		if res, err := s.AddReport(in); err != nil || res.Outcome != ReportStored {
			t.Errorf("%s: %+v %v", name, res, err)
		}
	}
	// After 24h the same report is new again.
	*now = now.Add(2 * time.Hour)
	if res, err := s.AddReport(rin(1)); err != nil || res.Outcome != ReportStored {
		t.Fatalf("after window: %+v %v", res, err)
	}
}

func TestAddReportDuplicateIgnoresResolvedReports(t *testing.T) {
	s, _ := reportStore(t)
	first, _ := s.AddReport(rin(1))
	if err := s.ResolveReport(99, first.ID, "handled"); err != nil {
		t.Fatal(err)
	}
	res, err := s.AddReport(rin(1))
	if err != nil || res.Outcome != ReportStored || res.ID == first.ID {
		t.Fatalf("a resolved report must not swallow a new one: %+v %v", res, err)
	}
}

func TestAddReportPerBundleCapDropsSilently(t *testing.T) {
	s, _ := reportStore(t)
	s.SetReportCaps(3, 1000)
	publish(t, s, 2, "bob", "y", "1.0.0")
	for i := 0; i < 3; i++ {
		if res, err := s.AddReport(rin(byte(i))); err != nil || res.Outcome != ReportStored {
			t.Fatalf("%d: %+v %v", i, res, err)
		}
	}
	res, err := s.AddReport(rin(50))
	if err != nil || res.Outcome != ReportDropped || res.ID != 0 {
		t.Fatalf("over cap: %+v %v", res, err)
	}
	if n := openCount(t, s); n != 3 {
		t.Fatalf("%d rows, want 3", n)
	}
	// Another bundle is unaffected.
	other := ReportInput{OwnerLogin: "bob", Name: "y", Reason: "other", Details: "d", ReporterKey: []byte{1}}
	if res, err := s.AddReport(other); err != nil || res.Outcome != ReportStored {
		t.Fatalf("other bundle: %+v %v", res, err)
	}
	// Resolving one frees a slot.
	if err := s.ResolveReport(99, 1, "ok"); err != nil {
		t.Fatal(err)
	}
	if res, err := s.AddReport(rin(51)); err != nil || res.Outcome != ReportStored {
		t.Fatalf("after resolve: %+v %v", res, err)
	}
}

func TestAddReportGlobalCapDropsSilently(t *testing.T) {
	s, _ := reportStore(t)
	s.SetReportCaps(100, 2)
	publish(t, s, 2, "bob", "y", "1.0.0")
	s.AddReport(rin(1))
	s.AddReport(ReportInput{OwnerLogin: "bob", Name: "y", Reason: "other", Details: "d", ReporterKey: []byte{1}})
	res, err := s.AddReport(rin(3))
	if err != nil || res.Outcome != ReportDropped {
		t.Fatalf("%+v %v", res, err)
	}
	if n := openCount(t, s); n != 2 {
		t.Fatalf("%d rows", n)
	}
}

func TestDefaultReportCaps(t *testing.T) {
	if MaxOpenReportsPerBundle != 200 || MaxOpenReports != 5000 {
		t.Fatalf("caps changed: %d %d", MaxOpenReportsPerBundle, MaxOpenReports)
	}
	s := openStore(t)
	if s.reportCapBundle != 200 || s.reportCapGlobal != 5000 {
		t.Fatalf("store defaults %d %d", s.reportCapBundle, s.reportCapGlobal)
	}
}

func TestListAndResolveReports(t *testing.T) {
	s, now := reportStore(t)
	a, _ := s.AddReport(rin(1))
	*now = now.Add(time.Minute)
	in := rin(2)
	in.ReporterUserID = 1
	b, _ := s.AddReport(in)
	*now = now.Add(time.Minute)
	c, _ := s.AddReport(rin(3))

	open, err := s.ListReports(ReportsOpen, 10, 0)
	if err != nil || len(open) != 3 || open[0].ID != c.ID || open[2].ID != a.ID {
		t.Fatalf("newest first: %+v %v", open, err)
	}
	if open[1].ReporterLogin != "alice" || open[1].ReporterID != 1 || open[0].ReporterID != 0 {
		t.Fatalf("reporter: %+v", open[1])
	}
	if err := s.ResolveReport(99, b.ID, "false alarm"); err != nil {
		t.Fatal(err)
	}
	if err := s.ResolveReport(99, b.ID, "again"); !errors.Is(err, ErrAlreadyResolved) {
		t.Fatalf("second resolve: %v", err)
	}
	if err := s.ResolveReport(99, 4242, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown id: %v", err)
	}
	if open, _ := s.ListReports(ReportsOpen, 10, 0); len(open) != 2 {
		t.Fatalf("open = %d", len(open))
	}
	res, _ := s.ListReports(ReportsResolved, 10, 0)
	if len(res) != 1 || res[0].Resolution != "false alarm" || !res[0].Resolved() || res[0].ResolvedAt.Unix() != now.Unix() {
		t.Fatalf("resolved: %+v", res)
	}
	all, _ := s.ListReports(ReportsAll, 10, 0)
	paged, _ := s.ListReports(ReportsAll, 1, 1)
	if len(all) != 3 || len(paged) != 1 || paged[0].ID != all[1].ID {
		t.Fatalf("paging: %d %+v", len(all), paged)
	}
	// Resolution is audited in the same transaction.
	log, _ := s.AdminLog(5)
	if len(log) != 1 || log[0].Action != "resolve_report" || log[0].Target != fmt.Sprintf("report:%d", b.ID) || log[0].Reason != "false alarm" {
		t.Fatalf("audit: %+v", log)
	}
}

func TestReportBundleStateReflectsTakedowns(t *testing.T) {
	s, _ := reportStore(t)
	s.AddReport(rin(1)) // 1.0.0
	whole := rin(2)
	whole.Version = ""
	s.AddReport(whole)
	state := func() map[string]string {
		rs, err := s.ListReports(ReportsAll, 10, 0)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, r := range rs {
			out[r.Version] = r.BundleState
		}
		return out
	}
	if st := state(); st["1.0.0"] != "live" || st[""] != "live" {
		t.Fatalf("%v", st)
	}
	s.RemoveVersion(99, "alice", "x", "1.0.0", "r")
	if st := state(); st["1.0.0"] != "removed" || st[""] != "live" {
		t.Fatalf("one version removed: %v", st)
	}
	s.RemoveBundle(99, "alice", "x", "r")
	if st := state(); st[""] != "removed" {
		t.Fatalf("bundle removed: %v", st)
	}
	s.BanUser(99, 1, "r")
	if st := state(); st["1.0.0"] != "owner-banned" || st[""] != "owner-banned" {
		t.Fatalf("banned: %v", st)
	}
}
