package api

import (
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Limiter is an in-memory sliding-window rate limiter keyed by string. It
// allows at most limit events per key within window. The clock is injectable
// so tests never sleep. Keys whose events have all expired are evicted
// periodically, so memory is bounded by the number of recently active keys.
type Limiter struct {
	limit  int
	window time.Duration
	now    func() time.Time

	mu        sync.Mutex
	hits      map[string][]time.Time
	lastSweep time.Time
}

// NewLimiter returns a Limiter; a nil now means time.Now.
func NewLimiter(limit int, window time.Duration, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{limit: limit, window: window, now: now, hits: map[string][]time.Time{}, lastSweep: now()}
}

// Allow records an event for key if the key is under its limit. When it is
// not, it returns false and how long until the oldest event leaves the window.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if now.Sub(l.lastSweep) >= l.window {
		for k, ts := range l.hits {
			if len(ts) == 0 || now.Sub(ts[len(ts)-1]) >= l.window {
				delete(l.hits, k)
			}
		}
		l.lastSweep = now
	}
	ts := l.hits[key]
	i := 0
	for i < len(ts) && now.Sub(ts[i]) >= l.window {
		i++
	}
	ts = ts[i:]
	if len(ts) >= l.limit {
		l.hits[key] = ts
		return false, ts[0].Add(l.window).Sub(now)
	}
	l.hits[key] = append(ts, now)
	return true, 0
}

// size reports the number of tracked keys (for tests).
func (l *Limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.hits)
}

func tooMany(w http.ResponseWriter, retry time.Duration) {
	secs := int((retry + time.Second - 1) / time.Second)
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	writeErr(w, http.StatusTooManyRequests, "rate limit exceeded; retry later")
}

// clientIP derives the caller's IP from r.RemoteAddr. X-Forwarded-For is
// attacker-controlled unless a trusted reverse proxy sets it, so it is only
// consulted (rightmost entry, the one our proxy appended) when trustProxy is
// true (TRUSTED_PROXY=true).
func clientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := splitComma(xff)
			if ip := parts[len(parts)-1]; ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			p := s[start:i]
			for len(p) > 0 && p[0] == ' ' {
				p = p[1:]
			}
			for len(p) > 0 && p[len(p)-1] == ' ' {
				p = p[:len(p)-1]
			}
			out = append(out, p)
			start = i + 1
		}
	}
	return out
}

// LimitByIP wraps h, rejecting requests over the per-IP limit with 429.
func LimitByIP(l *Limiter, trustProxy bool, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, retry := l.Allow(clientIP(r, trustProxy)); !ok {
			tooMany(w, retry)
			return
		}
		h.ServeHTTP(w, r)
	})
}
