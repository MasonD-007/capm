package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type recv struct {
	mu   sync.Mutex
	reqs []recvReq
	ch   chan struct{}
}
type recvReq struct {
	method, ctype string
	body          []byte
}

func newRecv() *recv { return &recv{ch: make(chan struct{}, 100)} }

func (r *recv) handler(status int, delay time.Duration, gate chan struct{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.reqs = append(r.reqs, recvReq{req.Method, req.Header.Get("Content-Type"), b})
		r.mu.Unlock()
		r.ch <- struct{}{}
		if gate != nil {
			<-gate
		}
		time.Sleep(delay)
		w.WriteHeader(status)
	})
}

func (r *recv) wait(t *testing.T, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-r.ch:
		case <-time.After(3 * time.Second):
			t.Fatalf("receiver got %d of %d requests", i, n)
		}
	}
}

func (r *recv) count() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.reqs) }

func TestWebhookPayloadShape(t *testing.T) {
	rc := newRecv()
	srv := httptest.NewServer(rc.handler(200, 0, nil))
	defer srv.Close()
	w := NewWebhook(WebhookConfig{URL: srv.URL + "/hook?token=SECRET", PublicURL: "https://reg.example/"})
	defer w.Close(time.Second)
	w.Notify(ReportEvent{ID: 42, Owner: "alice", Name: "x", Version: "1.0.0", Reason: "malware",
		Details: "line one\nline two\t‮ " + strings.Repeat("z", 400)})
	rc.wait(t, 1)
	rc.mu.Lock()
	got := rc.reqs[0]
	rc.mu.Unlock()
	if got.method != "POST" || got.ctype != "application/json" {
		t.Fatalf("%+v", got)
	}
	var p map[string]any
	if err := json.Unmarshal(got.body, &p); err != nil {
		t.Fatal(err)
	}
	if p["text"] != "New capm report (malware): alice/x@1.0.0" || p["bundle"] != "alice/x" || p["version"] != "1.0.0" ||
		p["reason"] != "malware" || p["reportId"] != float64(42) || p["url"] != "https://reg.example/bundles/alice/x" {
		t.Fatalf("%s", got.body)
	}
	d, _ := p["details"].(string)
	if strings.ContainsAny(d, "\n\t‮") || len([]rune(d)) > 201 || !strings.HasPrefix(d, "line one line two ") {
		t.Fatalf("details %q", d)
	}
	if strings.Contains(p["text"].(string), "line one") {
		t.Fatal("free text must never be in text")
	}
	if len(p) != 7 {
		t.Fatalf("unexpected keys: %s", got.body)
	}
}

func TestWebhookWholeBundleAndNoPublicURL(t *testing.T) {
	rc := newRecv()
	srv := httptest.NewServer(rc.handler(200, 0, nil))
	defer srv.Close()
	w := NewWebhook(WebhookConfig{URL: srv.URL})
	defer w.Close(time.Second)
	w.Notify(ReportEvent{ID: 1, Owner: "alice", Name: "x", Reason: "other", Details: "d"})
	rc.wait(t, 1)
	var p map[string]any
	json.Unmarshal(rc.reqs[0].body, &p)
	if p["text"] != "New capm report (other): alice/x" || p["version"] != "" {
		t.Fatalf("%v", p)
	}
	if _, ok := p["url"]; ok {
		t.Fatalf("url must be omitted without PUBLIC_URL: %v", p)
	}
}

func TestReportWithoutNotifierMakesNoRequest(t *testing.T) {
	rc := newRecv()
	srv := httptest.NewServer(rc.handler(200, 0, nil))
	defer srv.Close()
	e := reportEnv(t, func(c *Config) { c.Notifier = nil })
	if r := e.report(t, "", valid()); r.code != 202 {
		t.Fatal(r)
	}
	time.Sleep(50 * time.Millisecond)
	if rc.count() != 0 {
		t.Fatal("request made with no webhook configured")
	}
}

func TestReportSubmitUnaffectedByFailingReceiver(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		delay  time.Duration
	}{"500": {500, 0}, "slow": {200, 600 * time.Millisecond}} {
		t.Run(name, func(t *testing.T) {
			rc := newRecv()
			srv := httptest.NewServer(rc.handler(tc.status, tc.delay, nil))
			defer srv.Close()
			w := NewWebhook(WebhookConfig{URL: srv.URL, Timeout: 100 * time.Millisecond})
			defer w.Close(time.Second)
			e := reportEnv(t, func(c *Config) { c.Notifier = w })
			start := time.Now()
			r := e.report(t, "", valid())
			if r.code != 202 || r.body != "{}" || time.Since(start) > 400*time.Millisecond {
				t.Fatalf("%+v after %v", r, time.Since(start))
			}
			rc.wait(t, 1)
			if n := len(e.open(t)); n != 1 {
				t.Fatalf("%d rows", n)
			}
			if rc.count() != 1 {
				t.Fatalf("no retries expected, receiver saw %d", rc.count())
			}
		})
	}
}

func TestWebhookQueueOverflowDrops(t *testing.T) {
	rc := newRecv()
	gate := make(chan struct{})
	srv := httptest.NewServer(rc.handler(200, 0, gate))
	defer srv.Close()
	w := NewWebhook(WebhookConfig{URL: srv.URL, QueueSize: 2})
	w.Notify(ReportEvent{ID: 1, Owner: "a", Name: "x", Reason: "other"})
	rc.wait(t, 1) // the worker is now stuck inside request 1
	start := time.Now()
	for i := 2; i <= 6; i++ {
		w.Notify(ReportEvent{ID: int64(i), Owner: "a", Name: "x", Reason: "other"})
	}
	if time.Since(start) > 200*time.Millisecond {
		t.Fatal("Notify must never block")
	}
	if d := w.Dropped(); d != 3 {
		t.Fatalf("dropped = %d, want 3 (queue of 2 behind one in flight)", d)
	}
	close(gate)
	rc.wait(t, 2)
	w.Close(time.Second)
	if rc.count() != 3 {
		t.Fatalf("receiver saw %d requests, want 3", rc.count())
	}
}

func TestWebhookCloseAbandonsAfterDeadlineAndStopsAccepting(t *testing.T) {
	rc := newRecv()
	gate := make(chan struct{})
	srv := httptest.NewServer(rc.handler(200, 0, gate))
	defer srv.Close()
	defer close(gate)
	w := NewWebhook(WebhookConfig{URL: srv.URL, Timeout: 10 * time.Second})
	w.Notify(ReportEvent{ID: 1, Owner: "a", Name: "x", Reason: "other"})
	rc.wait(t, 1)
	start := time.Now()
	w.Close(150 * time.Millisecond)
	if d := time.Since(start); d > time.Second {
		t.Fatalf("Close took %v with a hung receiver", d)
	}
	w.Notify(ReportEvent{ID: 2, Owner: "a", Name: "x", Reason: "other"}) // must not panic
	w.Close(time.Second)                                                 // idempotent
}

func TestWebhookDoesNotFollowRedirects(t *testing.T) {
	hit := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit <- struct{}{} }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	w := NewWebhook(WebhookConfig{URL: srv.URL})
	w.Notify(ReportEvent{ID: 1, Owner: "a", Name: "x", Reason: "other"})
	w.Close(time.Second)
	select {
	case <-hit:
		t.Fatal("redirect was followed")
	default:
	}
}

func TestWebhookHostForLogsNeverHasURLSecrets(t *testing.T) {
	if got := hostOnly("https://user:pw@hooks.example.com:8443/services/T0/B0/SECRET?x=1"); got != "hooks.example.com:8443" {
		t.Fatalf("%q", got)
	}
}
