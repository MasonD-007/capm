package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func TestLimiterSlidingWindow(t *testing.T) {
	c := &fakeClock{time.Unix(1000, 0)}
	l := NewLimiter(3, time.Hour, c.now)
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("event %d denied", i)
		}
		c.t = c.t.Add(10 * time.Minute)
	}
	ok, retry := l.Allow("a")
	if ok || retry != 30*time.Minute {
		t.Fatalf("ok=%v retry=%v", ok, retry)
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("keys must be independent")
	}
	c.t = c.t.Add(30 * time.Minute) // first event leaves the window
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("should allow after window slides")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("window is full again")
	}
}

func TestLimiterEvicts(t *testing.T) {
	c := &fakeClock{time.Unix(1000, 0)}
	l := NewLimiter(1, time.Minute, c.now)
	for _, k := range []string{"a", "b", "c", "d"} {
		l.Allow(k)
	}
	if l.size() != 4 {
		t.Fatalf("size %d", l.size())
	}
	c.t = c.t.Add(2 * time.Minute)
	l.Allow("e")
	if l.size() != 1 {
		t.Fatalf("stale keys not evicted: %d", l.size())
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "1.2.3.4:5555"
	r.Header.Set("X-Forwarded-For", "9.9.9.9, 8.8.8.8")
	if got := clientIP(r, false); got != "1.2.3.4" {
		t.Fatalf("untrusted: %s", got)
	}
	if got := clientIP(r, true); got != "8.8.8.8" {
		t.Fatalf("trusted: %s", got)
	}
}

func TestLimitByIPRetryAfter(t *testing.T) {
	l := NewLimiter(1, time.Minute, nil)
	h := LimitByIP(l, false, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	do := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/", nil)
		r.RemoteAddr = "1.2.3.4:1"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if do().Code != 200 {
		t.Fatal("first")
	}
	w := do()
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
}
