package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func reportsJSON(t *testing.T, items ...map[string]any) string {
	t.Helper()
	b, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func rep(id int, over map[string]any) map[string]any {
	m := map[string]any{"id": id, "owner": "bob", "name": "agent", "version": "1.0.0", "reason": "malware",
		"details": "steals keys", "reporterLoggedIn": false, "createdAt": time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339),
		"bundleState": "live"}
	for k, v := range over {
		m[k] = v
	}
	return m
}

func TestAdminReportsListRequestsAndTable(t *testing.T) {
	a, run := adminHarness(t)
	a.reply = reportsJSON(t, rep(2, map[string]any{"version": "", "bundleState": "removed", "details": "line one\nline two"}),
		rep(1, map[string]any{"bundleState": "owner-banned", "resolvedAt": time.Now().UTC().Format(time.RFC3339)}))
	code, out, errb := run("reports")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	if r := a.reqs[0]; r.method != "GET" || !strings.HasPrefix(r.path, "/v1/admin/reports?") || !strings.Contains(r.path, "state=open") || r.auth != "Bearer tok-123" {
		t.Fatalf("%+v", r)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("want header + 2 rows:\n%s", out)
	}
	for _, h := range []string{"ID", "BUNDLE", "VERSION", "REASON", "AGE", "STATE", "DETAILS"} {
		if !strings.Contains(lines[0], h) {
			t.Errorf("header lacks %s: %q", h, lines[0])
		}
	}
	if !strings.Contains(lines[1], "bob/agent") || !strings.Contains(lines[1], "removed") || !strings.Contains(lines[1], "3h") ||
		!strings.Contains(lines[1], "line one") || strings.Contains(lines[1], "line two") {
		t.Errorf("row 1: %q", lines[1])
	}
	if !strings.Contains(lines[2], "owner-banned") || !strings.Contains(lines[2], "resolved") {
		t.Errorf("row 2: %q", lines[2])
	}
	for flag, state := range map[string]string{"--all": "all", "--resolved": "resolved"} {
		a.reqs = nil
		if code, _, errb := run("reports", flag); code != 0 || !strings.Contains(a.reqs[0].path, "state="+state) {
			t.Errorf("%s: %d %s %v", flag, code, errb, a.reqs)
		}
	}
	if code, _, _ := run("reports", "--all", "--resolved"); code != 2 {
		t.Errorf("both flags: %d", code)
	}
	if code, _, _ := run("reports", "extra"); code != 2 {
		t.Errorf("extra arg: %d", code)
	}
}

func TestAdminReportsTableSurvivesHostileDetails(t *testing.T) {
	a, run := adminHarness(t)
	evil := []string{
		"\x1b[2J\x1b[31mred\x1b]0;pwned\x07",
		"‮evil‬ ⁦x⁩",
		"first\nSECOND LINE",
		"\tcolumn\tbreak\t",
		"\r\n\r\nstart-of-line\roverwrite",
		strings.Repeat("A", 500),
		"\u0085next line",
	}
	var items []map[string]any
	for i, d := range evil {
		items = append(items, rep(i+1, map[string]any{"details": d, "owner": "o\x1b[1m", "name": "n‮", "reason": "r\nx", "version": "1\t2"}))
	}
	a.reply = reportsJSON(t, items...)
	code, out, errb := run("reports")
	if code != 0 {
		t.Fatalf("%d %s", code, errb)
	}
	if strings.ContainsAny(out, "\x1b\x07\r‮‬⁦⁩\u0085 ") {
		t.Fatalf("control or bidi characters reached the terminal: %q", out)
	}
	if got := strings.Count(out, "\n"); got != len(evil)+1 {
		t.Fatalf("%d lines for %d reports (header included): %q", got, len(evil), out)
	}
	if strings.Contains(out, "\t") {
		t.Fatalf("tab inside a cell: %q", out)
	}
	for _, l := range strings.Split(out, "\n") {
		if len([]rune(l)) > 220 {
			t.Fatalf("row too long (%d): %q", len(l), l)
		}
	}
	if strings.Contains(out, "SECOND LINE") {
		t.Fatal("only the first line of details belongs in the table")
	}
}

func TestAdminReportShowsFullDetailsSafely(t *testing.T) {
	a, run := adminHarness(t)
	one := rep(5, map[string]any{"details": "line one\n\tindented\x1b[2J\nline ‮two\n" + strings.Repeat("z", 1500),
		"reporterLoggedIn": true, "reporter": "carol\x1b[1m", "bundleState": "removed"})
	b, _ := json.Marshal(one)
	a.reply = string(b)
	code, out, errb := run("report", "5")
	if code != 0 {
		t.Fatalf("%d %s", code, errb)
	}
	if r := a.reqs[0]; r.method != "GET" || r.path != "/v1/admin/reports/5" {
		t.Fatalf("%+v", r)
	}
	if strings.ContainsAny(out, "\x1b‮\r") {
		t.Fatalf("unsafe: %q", out)
	}
	for _, want := range []string{"bob/agent@1.0.0", "malware", "carol", "removed", "line one", "indented", "line two", strings.Repeat("z", 1500)} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	// Details are indented so they cannot be mistaken for the fields above.
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "line two") && !strings.HasPrefix(l, "  ") {
			t.Errorf("details line not indented: %q", l)
		}
	}
	if code, _, _ := run("report", "abc"); code != 2 {
		t.Errorf("non-numeric id: %d", code)
	}
	if code, _, _ := run("report"); code != 2 {
		t.Errorf("no id: %d", code)
	}
}

func TestAdminResolveReport(t *testing.T) {
	a, run := adminHarness(t)
	a.reply = `{"id":4,"resolved":true}`
	code, out, errb := run("resolve", "4", "--note", "removed the bundle")
	if code != 0 {
		t.Fatalf("%d %s", code, errb)
	}
	r := a.reqs[0]
	var body map[string]string
	json.Unmarshal([]byte(r.body), &body)
	if r.method != "POST" || r.path != "/v1/admin/reports/4/resolve" || body["resolution"] != "removed the bundle" || !strings.Contains(out, "4") {
		t.Fatalf("%+v %q", r, out)
	}
	for name, args := range map[string][]string{
		"no note": {"resolve", "4"}, "blank note": {"resolve", "4", "--note", " "}, "no id": {"resolve", "--note", "x"},
		"bad id": {"resolve", "x", "--note", "y"}, "note too long": {"resolve", "4", "--note", strings.Repeat("a", 501)},
		"unknown flag": {"resolve", "4", "--note", "x", "--reason", "y"},
	} {
		n := len(a.reqs)
		if code, _, _ := run(args...); code != 2 || len(a.reqs) != n {
			t.Errorf("%s: exit %d, requests %d", name, code, len(a.reqs)-n)
		}
	}
	a.status, a.reply = 409, `{"error":"already resolved"}`
	if code, _, errb := run("resolve", "4", "--note", "again"); code != 1 || !strings.Contains(errb, "already resolved") {
		t.Errorf("409: %d %q", code, errb)
	}
	a.status, a.reply = 404, `404 page not found`
	if code, _, errb := run("resolve", "4", "--note", "x"); code != 1 || !strings.Contains(errb, "not found") {
		t.Errorf("404: %d %q", code, errb)
	}
}

func TestAdminReportsEmpty(t *testing.T) {
	a, run := adminHarness(t)
	a.reply = `[]`
	code, out, errb := run("reports")
	if code != 0 || out != "" || !strings.Contains(errb, "no open reports") {
		t.Fatalf("%d %q %q", code, out, errb)
	}
}

func TestAdminUsageMentionsReports(t *testing.T) {
	_, run := adminHarness(t)
	_, out, _ := run()
	for _, w := range []string{"admin reports", "admin report ", "admin resolve"} {
		if !strings.Contains(out, w) {
			t.Errorf("usage lacks %q", w)
		}
	}
}
