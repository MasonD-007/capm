package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MasonD-007/capm/backend/internal/store"
)

type notifySpy struct {
	mu  sync.Mutex
	got []ReportEvent
}

func (n *notifySpy) Notify(ev ReportEvent) { n.mu.Lock(); n.got = append(n.got, ev); n.mu.Unlock() }
func (n *notifySpy) events() []ReportEvent {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]ReportEvent(nil), n.got...)
}

type renv struct {
	*env
	s   *store.Store
	spy *notifySpy
	clk *fakeClock
}

// reportEnv serves the real handler; the client IP comes from X-Test-IP
// (CLIENT_IP_HEADER) so tests can be many "visitors". Alice (1) owns x@1.0.0
// and x@1.1.0 (yanked); the admin is 99.
func reportEnv(t *testing.T, mod func(*Config)) *renv {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	e := &env{dir: dir}
	e.user = &struct {
		id    int64
		login string
		ok    bool
	}{1, "alice", true}
	spy := &notifySpy{}
	clk := &fakeClock{time.Unix(1_800_000_000, 0)}
	s.SetClock(clk.now)
	cfg := Config{
		IsAdmin:        func(id int64) bool { return id == adminID },
		ClientIPHeader: "X-Test-IP",
		Now:            clk.now,
		Notifier:       spy,
	}
	if mod != nil {
		mod(&cfg)
	}
	a := NewWithConfig(s, func(r *http.Request) (int64, string, bool) {
		if r.Header.Get("X-Test-Token") == "bad" {
			return 0, "", false
		}
		return e.user.id, e.user.login, e.user.ok
	}, cfg)
	e.srv = httptest.NewServer(a.Handler())
	t.Cleanup(e.srv.Close)
	re := &renv{env: e, s: s, spy: spy, clk: clk}
	publishVersions(t, e, "1.0.0", "1.1.0")
	if c, b := e.do(t, "POST", "/v1/bundles/alice/x/1.1.0/yank", nil); c != 200 {
		t.Fatalf("yank: %d %s", c, b)
	}
	return re
}

type rresp struct {
	code int
	body string
	hdr  http.Header
}

func (e *renv) post(t *testing.T, ip, path, ctype string, body []byte, hdr ...string) rresp {
	t.Helper()
	req, _ := http.NewRequest("POST", e.srv.URL+path, bytes.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if ip != "" {
		req.Header.Set("X-Test-IP", ip)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return rresp{resp.StatusCode, strings.TrimSpace(string(b)), resp.Header}
}

func (e *renv) report(t *testing.T, ip string, in map[string]any) rresp {
	t.Helper()
	b, _ := json.Marshal(in)
	return e.post(t, ip, "/v1/bundles/alice/x/report", "application/json", b)
}

func valid() map[string]any {
	return map[string]any{"version": "1.0.0", "reason": "malware", "details": "it steals keys"}
}

func (e *renv) open(t *testing.T) []store.Report {
	t.Helper()
	rs, err := e.s.ListReports(store.ReportsOpen, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func TestReportAnonymousAccepted(t *testing.T) {
	e := reportEnv(t, nil)
	e.user.ok = false
	r := e.report(t, "1.1.1.1", valid())
	// 202 with an empty object: an id would be a sequential counter that
	// tells every anonymous caller how many reports the registry has.
	if r.code != 202 || r.body != "{}" {
		t.Fatalf("%d %q", r.code, r.body)
	}
	rs := e.open(t)
	if len(rs) != 1 || rs[0].Reason != "malware" || rs[0].Details != "it steals keys" || rs[0].Version != "1.0.0" || rs[0].ReporterID != 0 {
		t.Fatalf("%+v", rs)
	}
}

func TestReportRecordsLoggedInUserAndTreatsBadTokenAsAnonymous(t *testing.T) {
	e := reportEnv(t, nil)
	e.user.id, e.user.login = 5, "carol"
	if r := e.report(t, "1.1.1.1", valid()); r.code != 202 {
		t.Fatalf("%+v", r)
	}
	b, _ := json.Marshal(map[string]any{"reason": "other", "details": "x"})
	if r := e.post(t, "2.2.2.2", "/v1/bundles/alice/x/report", "application/json", b, "X-Test-Token", "bad"); r.code != 202 {
		t.Fatalf("bad token must not be an error: %+v", r)
	}
	rs := e.open(t)
	if len(rs) != 2 || rs[0].ReporterID != 0 || rs[1].ReporterID != 5 {
		t.Fatalf("%+v", rs)
	}
}

func TestReportValidation(t *testing.T) {
	e := reportEnv(t, func(c *Config) { c.ReportPerHour = 1000 })
	long := strings.Repeat("a", 2001)
	cases := []struct {
		name string
		in   map[string]any
		want string // substring of the error
	}{
		{"no reason", map[string]any{"details": "x"}, "reason"},
		{"bad reason", map[string]any{"reason": "spam"}, "reason"},
		{"reason case", map[string]any{"reason": "Malware"}, "reason"},
		{"other needs details", map[string]any{"reason": "other"}, "details"},
		{"other whitespace details", map[string]any{"reason": "other", "details": " \n\t "}, "details"},
		{"details too long", map[string]any{"reason": "malware", "details": long}, "2000"},
		{"unknown version", map[string]any{"reason": "malware", "version": "9.9.9"}, "version"},
		{"version wrong type", map[string]any{"reason": "malware", "version": 3}, ""},
		{"unknown field", map[string]any{"reason": "malware", "reporter": "me"}, ""},
	}
	for _, c := range cases {
		r := e.report(t, "", c.in)
		if r.code != 400 || !strings.Contains(r.body, c.want) {
			t.Errorf("%s: %d %s", c.name, r.code, r.body)
		}
	}
	for name, body := range map[string]string{
		"not json": `nope`, "empty": ``, "trailing": `{"reason":"malware"} {"reason":"malware"}`,
		"array": `[]`, "bad utf8": "{\"reason\":\"other\",\"details\":\"a\xffb\"}",
	} {
		if r := e.post(t, "", "/v1/bundles/alice/x/report", "application/json", []byte(body)); r.code != 400 {
			t.Errorf("%s: %d %s", name, r.code, r.body)
		}
	}
	for _, ct := range []string{"", "text/plain", "application/x-www-form-urlencoded", "application/jsonx"} {
		if r := e.post(t, "", "/v1/bundles/alice/x/report", ct, []byte(`{"reason":"malware"}`)); r.code != 415 {
			t.Errorf("content-type %q: %d %s", ct, r.code, r.body)
		}
	}
	if r := e.post(t, "", "/v1/bundles/alice/x/report", "application/json; charset=utf-8", []byte(`{"reason":"malware"}`)); r.code != 202 {
		t.Errorf("charset param: %d %s", r.code, r.body)
	}
	if n := len(e.open(t)); n != 1 {
		t.Errorf("%d rows stored, want only the valid one", n)
	}
}

func TestReportBodyCap(t *testing.T) {
	e := reportEnv(t, nil)
	body := []byte(`{"reason":"other","details":"` + strings.Repeat("a", 9000) + `"}`)
	if r := e.post(t, "", "/v1/bundles/alice/x/report", "application/json", body); r.code != 413 {
		t.Fatalf("%d %s", r.code, r.body)
	}
	// 2000 four-byte characters (the most the limit allows) still fit.
	ok := map[string]any{"reason": "other", "details": strings.Repeat("😀", 2000)}
	if r := e.report(t, "9.9.9.9", ok); r.code != 202 {
		t.Fatalf("max-size valid details: %d %s", r.code, r.body)
	}
	ok["details"] = strings.Repeat("😀", 2001)
	if r := e.report(t, "9.9.9.8", ok); r.code != 400 {
		t.Fatalf("2001 chars: %d %s", r.code, r.body)
	}
}

func TestReportDetailsAreSanitised(t *testing.T) {
	e := reportEnv(t, func(c *Config) { c.ReportPerHour = 1000 })
	in := valid()
	in["details"] = "  line1\r\nline2\tx\x00\x07\x1b[31mred\u202eevil\u2066\u200b \x7f\u0085 \n"
	if r := e.report(t, "", in); r.code != 202 {
		t.Fatalf("%+v", r)
	}
	got := e.open(t)[0].Details
	// Trimmed; newline and tab kept; every other control and bidi/format
	// character gone.
	want := "line1\nline2\tx[31mredevil"
	if got != want {
		t.Fatalf("details = %q, want %q", got, want)
	}
}

func TestReportNotFoundCases(t *testing.T) {
	e := reportEnv(t, func(c *Config) { c.ReportPerHour = 1000 })
	for _, p := range []string{"/v1/bundles/alice/nope/report", "/v1/bundles/nobody/x/report", "/v1/bundles/~1/x/report"} {
		if r := e.post(t, "", p, "application/json", []byte(`{"reason":"malware"}`)); r.code != 404 {
			t.Errorf("%s: %d %s", p, r.code, r.body)
		}
	}
	// Yanked and removed versions can be reported.
	if r := e.report(t, "", map[string]any{"reason": "malware", "version": "1.1.0"}); r.code != 202 {
		t.Errorf("yanked: %d %s", r.code, r.body)
	}
	if _, err := e.s.RemoveVersion(adminID, "alice", "x", "1.0.0", "bad"); err != nil {
		t.Fatal(err)
	}
	if r := e.report(t, "", map[string]any{"reason": "malware", "version": "1.0.0"}); r.code != 202 {
		t.Errorf("removed: %d %s", r.code, r.body)
	}
	// A banned owner's bundle answers like one that does not exist.
	if err := e.s.BanUser(adminID, 1, "x"); err != nil {
		t.Fatal(err)
	}
	if r := e.report(t, "", valid()); r.code != 404 {
		t.Errorf("banned owner: %d %s", r.code, r.body)
	}
}

func TestReportRateLimitPerClientIP(t *testing.T) {
	e := reportEnv(t, nil)
	for i := 0; i < 5; i++ {
		in := valid()
		in["details"] = strings.Repeat("d", i+1) // distinct, so none is a duplicate
		if r := e.report(t, "3.3.3.3", in); r.code != 202 {
			t.Fatalf("%d: %+v", i, r)
		}
	}
	r := e.report(t, "3.3.3.3", valid())
	if r.code != 429 || r.hdr.Get("Retry-After") == "" {
		t.Fatalf("6th: %+v", r)
	}
	if r := e.report(t, "4.4.4.4", valid()); r.code != 202 {
		t.Fatalf("another IP: %+v", r)
	}
	e.clk.t = e.clk.t.Add(time.Hour + time.Second)
	if r := e.report(t, "3.3.3.3", valid()); r.code != 202 {
		t.Fatalf("after the hour: %+v", r)
	}
}

func TestReportRateLimitUsesSameClientIPLogicAsAuth(t *testing.T) {
	// No header, no TRUSTED_PROXY: X-Forwarded-For is ignored, so a spoofed
	// value cannot dodge the limit.
	e := reportEnv(t, func(c *Config) { c.ClientIPHeader = ""; c.ReportPerHour = 2 })
	for i, xff := range []string{"1.1.1.1", "2.2.2.2"} {
		in := valid()
		in["details"] = strings.Repeat("d", i+1)
		if r := e.post(t, "", "/v1/bundles/alice/x/report", "application/json", mustJSON(in), "X-Forwarded-For", xff); r.code != 202 {
			t.Fatalf("%d: %+v", i, r)
		}
	}
	if r := e.post(t, "", "/v1/bundles/alice/x/report", "application/json", mustJSON(valid()), "X-Forwarded-For", "3.3.3.3"); r.code != 429 {
		t.Fatalf("spoofed X-Forwarded-For must not evade the limit: %+v", r)
	}
	// With TRUSTED_PROXY the rightmost entry is the client.
	e2 := reportEnv(t, func(c *Config) { c.ClientIPHeader = ""; c.TrustProxy = true; c.ReportPerHour = 1 })
	if r := e2.post(t, "", "/v1/bundles/alice/x/report", "application/json", mustJSON(valid()), "X-Forwarded-For", "6.6.6.6, 7.7.7.7"); r.code != 202 {
		t.Fatalf("%+v", r)
	}
	if r := e2.post(t, "", "/v1/bundles/alice/x/report", "application/json", mustJSON(valid()), "X-Forwarded-For", "8.8.8.8, 7.7.7.7"); r.code != 429 {
		t.Fatalf("same rightmost entry shares a bucket: %+v", r)
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestReportRateIsConfigurableAndZeroDisables(t *testing.T) {
	e := reportEnv(t, func(c *Config) { c.ReportPerHour = 1 })
	if r := e.report(t, "1.1.1.1", valid()); r.code != 202 {
		t.Fatal(r)
	}
	in := valid()
	in["details"] = "other"
	if r := e.report(t, "1.1.1.1", in); r.code != 429 {
		t.Fatalf("limit 1: %+v", r)
	}
	off := reportEnv(t, func(c *Config) { c.ReportsDisabled = true })
	if r := off.report(t, "1.1.1.1", valid()); r.code != 404 {
		t.Fatalf("disabled: %+v", r)
	}
	if n := len(off.open(t)); n != 0 {
		t.Fatalf("%d stored while disabled", n)
	}
}

func TestReportDuplicateLooksLikeSuccessAndInsertsNothing(t *testing.T) {
	spy := &notifySpy{}
	e := reportEnv(t, func(c *Config) { c.Notifier = spy })
	first := e.report(t, "1.1.1.1", valid())
	again := e.report(t, "1.1.1.1", valid())
	if first.code != again.code || first.body != again.body {
		t.Fatalf("first %+v, duplicate %+v", first, again)
	}
	if n := len(e.open(t)); n != 1 {
		t.Fatalf("%d rows", n)
	}
	if n := len(spy.events()); n != 1 {
		t.Fatalf("%d notifications for one stored report", n)
	}
	// A different reporter is a different report.
	if r := e.report(t, "2.2.2.2", valid()); r.code != 202 || len(e.open(t)) != 2 {
		t.Fatalf("%+v", r)
	}
}

func TestReportKeyIsSaltedKeyedHashNotTheIP(t *testing.T) {
	a := reporterKey([]byte("salt-one"), "203.0.113.9")
	if len(a) != 32 || bytes.Contains(a, []byte("203.0.113.9")) {
		t.Fatalf("%x", a)
	}
	if !bytes.Equal(a, reporterKey([]byte("salt-one"), "203.0.113.9")) {
		t.Fatal("not deterministic within a process")
	}
	if bytes.Equal(a, reporterKey([]byte("salt-two"), "203.0.113.9")) {
		t.Fatal("a different salt (a restart) must give a different key")
	}
	if bytes.Equal(a, reporterKey([]byte("salt-one"), "203.0.113.10")) {
		t.Fatal("different IPs must differ")
	}
	s1, s2 := newReportSalt(), newReportSalt()
	if len(s1) != 32 || bytes.Equal(s1, s2) {
		t.Fatal("salt must be random per call")
	}
}

func TestReportCapsLookLikeSuccess(t *testing.T) {
	e := reportEnv(t, func(c *Config) { c.ReportPerHour = 1000 })
	e.s.SetReportCaps(2, 1000)
	var bodies []string
	for i := 0; i < 4; i++ {
		in := valid()
		r := e.report(t, "10.0.0."+strings.Repeat("1", i+1), in)
		if r.code != 202 {
			t.Fatalf("%d: %+v", i, r)
		}
		bodies = append(bodies, r.body)
	}
	if n := len(e.open(t)); n != 2 {
		t.Fatalf("%d stored, cap is 2", n)
	}
	for _, b := range bodies {
		if b != bodies[0] {
			t.Fatalf("responses differ: %v", bodies)
		}
	}
	if n := len(e.spy.events()); n != 2 {
		t.Fatalf("%d notifications, want only the 2 stored", n)
	}
	e.s.SetReportCaps(1000, 2) // global cap: already 2 open
	in := valid()
	in["reason"], in["details"] = "other", "x"
	if r := e.report(t, "", in); r.code != 202 || len(e.open(t)) != 2 {
		t.Fatalf("global cap: %+v", r)
	}
}

func TestReportNotifiesOncePerStoredReport(t *testing.T) {
	e := reportEnv(t, nil)
	e.report(t, "1.1.1.1", valid())
	evs := e.spy.events()
	if len(evs) != 1 {
		t.Fatalf("%+v", evs)
	}
	got := evs[0]
	if got.ID == 0 || got.Owner != "alice" || got.Name != "x" || got.Version != "1.0.0" || got.Reason != "malware" || got.Details != "it steals keys" {
		t.Fatalf("%+v", got)
	}
}

func TestReportRouteDoesNotDisturbOtherRoutes(t *testing.T) {
	e := reportEnv(t, nil)
	// A version literally named "report" still addresses the metadata route.
	if c, _ := e.do(t, "GET", "/v1/bundles/alice/x/report", nil); c != 404 && c != 405 {
		t.Fatalf("GET report = %d", c)
	}
	if c, _ := e.do(t, "GET", "/v1/bundles/alice/x/1.0.0", nil); c != 200 {
		t.Fatalf("metadata = %d", c)
	}
}
