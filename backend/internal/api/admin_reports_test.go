package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

type adminReport struct {
	ID               int64      `json:"id"`
	Owner            string     `json:"owner"`
	Name             string     `json:"name"`
	Version          string     `json:"version"`
	Reason           string     `json:"reason"`
	Details          string     `json:"details"`
	ReporterLoggedIn bool       `json:"reporterLoggedIn"`
	Reporter         string     `json:"reporter"`
	CreatedAt        time.Time  `json:"createdAt"`
	ResolvedAt       *time.Time `json:"resolvedAt"`
	ResolvedBy       string     `json:"resolvedBy"`
	Resolution       string     `json:"resolution"`
	BundleState      string     `json:"bundleState"`
}

func seedReports(t *testing.T, e *renv) {
	t.Helper()
	e.s.UpsertUser(5, "carol")
	e.s.UpsertUser(adminID, "root")
	e.user.ok = false
	e.report(t, "1.1.1.1", map[string]any{"reason": "malware", "version": "1.0.0", "details": "first\nsecond"})
	e.clk.t = e.clk.t.Add(time.Minute)
	e.user.ok, e.user.id, e.user.login = true, 5, "carol"
	e.report(t, "2.2.2.2", map[string]any{"reason": "impersonation"})
	e.clk.t = e.clk.t.Add(time.Minute)
	e.asAdmin()
}

func (e *renv) list(t *testing.T, q string) []adminReport {
	t.Helper()
	c, b := e.do(t, "GET", "/v1/admin/reports"+q, nil)
	if c != 200 {
		t.Fatalf("list%s: %d %s", q, c, b)
	}
	if strings.Contains(strings.ToLower(string(b)), "reporter_key") || strings.Contains(strings.ToLower(string(b)), "reporterkey") {
		t.Fatalf("reporter key leaked: %s", b)
	}
	var out []adminReport
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestAdminReportsAre404ForNonAdmins(t *testing.T) {
	e := reportEnv(t, nil)
	seedReports(t, e)
	routes := [][2]string{{"GET", "/v1/admin/reports"}, {"GET", "/v1/admin/reports/1"}, {"POST", "/v1/admin/reports/1/resolve"}}
	for _, who := range []string{"alice", "nobody"} {
		if who == "alice" {
			e.asAlice()
		} else {
			e.asNobody()
		}
		for _, r := range routes {
			if c, _ := e.do(t, r[0], r[1], []byte(`{"resolution":"x"}`)); c != 404 {
				t.Errorf("%s %s %s: %d, want 404", who, r[0], r[1], c)
			}
		}
	}
	if n := len(e.open(t)); n != 2 {
		t.Fatalf("a non-admin changed something: %d open", n)
	}
}

func TestAdminListReports(t *testing.T) {
	e := reportEnv(t, nil)
	seedReports(t, e)
	rs := e.list(t, "")
	if len(rs) != 2 || rs[0].Reason != "impersonation" || rs[1].Reason != "malware" {
		t.Fatalf("newest first: %+v", rs)
	}
	if !rs[0].ReporterLoggedIn || rs[0].Reporter != "carol" || rs[1].ReporterLoggedIn || rs[1].Reporter != "" {
		t.Fatalf("reporter: %+v", rs)
	}
	m := rs[1]
	if m.Owner != "alice" || m.Name != "x" || m.Version != "1.0.0" || m.Details != "first\nsecond" ||
		m.ResolvedAt != nil || m.BundleState != "live" || m.CreatedAt.IsZero() || m.ID == 0 {
		t.Fatalf("%+v", m)
	}
	if got := e.list(t, "?limit=1&offset=1"); len(got) != 1 || got[0].ID != m.ID {
		t.Fatalf("paging: %+v", got)
	}
	for _, bad := range []string{"?state=nope", "?limit=0", "?limit=x", "?offset=-1", "?offset=x"} {
		if c, _ := e.do(t, "GET", "/v1/admin/reports"+bad, nil); c != 400 {
			t.Errorf("%s: %d, want 400", bad, c)
		}
	}
	if got := e.list(t, "?state=resolved"); len(got) != 0 {
		t.Fatalf("resolved: %+v", got)
	}
}

func TestAdminGetAndResolveReport(t *testing.T) {
	e := reportEnv(t, nil)
	seedReports(t, e)
	id := e.list(t, "")[1].ID
	c, b := e.do(t, "GET", fmt.Sprintf("/v1/admin/reports/%d", id), nil)
	var one adminReport
	if c != 200 || json.Unmarshal(b, &one) != nil || one.ID != id || one.Details != "first\nsecond" {
		t.Fatalf("%d %s", c, b)
	}
	for _, p := range []string{"/v1/admin/reports/9999", "/v1/admin/reports/abc", "/v1/admin/reports/-1"} {
		if c, _ := e.do(t, "GET", p, nil); c != 404 && c != 400 {
			t.Errorf("%s: %d", p, c)
		}
	}
	if c, _ := e.do(t, "GET", "/v1/admin/reports/9999", nil); c != 404 {
		t.Errorf("unknown id = %d", c)
	}

	path := fmt.Sprintf("/v1/admin/reports/%d/resolve", id)
	for name, body := range map[string]string{
		"empty": `{"resolution":""}`, "blank": `{"resolution":"  "}`, "missing": `{}`, "not json": `x`,
		"long": `{"resolution":"` + strings.Repeat("a", 501) + `"}`, "unknown field": `{"resolution":"a","x":1}`,
	} {
		if c, b := e.do(t, "POST", path, []byte(body)); c != 400 {
			t.Errorf("%s: %d %s", name, c, b)
		}
	}
	if c, b := e.do(t, "POST", "/v1/admin/reports/9999/resolve", []byte(`{"resolution":"a"}`)); c != 404 {
		t.Errorf("unknown: %d %s", c, b)
	}
	if c, b := e.do(t, "POST", path, []byte(`{"resolution":"removed the bundle"}`)); c != 200 {
		t.Fatalf("resolve: %d %s", c, b)
	}
	if c, _ := e.do(t, "POST", path, []byte(`{"resolution":"again"}`)); c != 409 {
		t.Fatalf("second resolve = %d, want 409", c)
	}
	if got := e.list(t, ""); len(got) != 1 {
		t.Fatalf("open after resolve: %+v", got)
	}
	got := e.list(t, "?state=resolved")
	if len(got) != 1 || got[0].ResolvedAt == nil || got[0].Resolution != "removed the bundle" || got[0].ResolvedBy != "root" {
		// root is the admin's login in adminEnv's fake auth
		t.Fatalf("%+v", got)
	}
	if all := e.list(t, "?state=all"); len(all) != 2 {
		t.Fatalf("all: %+v", all)
	}
	// Audited.
	_, lb := e.do(t, "GET", "/v1/admin/log", nil)
	if !strings.Contains(string(lb), `"resolve_report"`) || !strings.Contains(string(lb), fmt.Sprintf("report:%d", id)) {
		t.Fatalf("audit log: %s", lb)
	}
}

func TestAdminReportsShowBundleStateAndAreNotAutoResolved(t *testing.T) {
	e := reportEnv(t, nil)
	seedReports(t, e)
	e.do(t, "POST", "/v1/admin/bundles/alice/x/1.0.0/remove", reason("bad"))
	rs := e.list(t, "")
	if len(rs) != 2 {
		t.Fatalf("removing must not resolve reports: %+v", rs)
	}
	byReason := map[string]adminReport{}
	for _, r := range rs {
		byReason[r.Reason] = r
	}
	if byReason["malware"].BundleState != "removed" || byReason["impersonation"].BundleState != "live" {
		t.Fatalf("%+v", byReason)
	}
	e.do(t, "POST", "/v1/admin/users/alice/ban", reason("bad"))
	for _, r := range e.list(t, "") {
		if r.BundleState != "owner-banned" {
			t.Errorf("%+v", r)
		}
	}
}
