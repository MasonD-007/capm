package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/MasonD-007/capm/backend/internal/store"
)

func setupCfg(t *testing.T, cfg Config) (*env, *fakeClock) {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	clk := &fakeClock{time.Unix(1_000_000, 0)}
	cfg.Now = clk.now
	e := &env{}
	e.user = &struct {
		id    int64
		login string
		ok    bool
	}{1, "alice", true}
	a := NewWithConfig(s, func(r *http.Request) (int64, string, bool) { return e.user.id, e.user.login, e.user.ok }, cfg)
	e.srv = httptest.NewServer(a.Handler())
	t.Cleanup(e.srv.Close)
	return e, clk
}

func TestOversizedBody413(t *testing.T) {
	e, _ := setupCfg(t, Config{MaxBundleBytes: 1024})
	c, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", make([]byte, 2048))
	if c != 413 {
		t.Fatalf("%d %s", c, b)
	}
}

func TestDefaultMaxIs5MiB(t *testing.T) {
	a := NewWithConfig(nil, nil, Config{})
	if a.cfg.MaxBundleBytes != 5<<20 || a.cfg.PublishPerHour != 30 {
		t.Fatalf("%+v", a.cfg)
	}
}

func TestPublishRate31st429(t *testing.T) {
	e, clk := setupCfg(t, Config{})
	for i := 0; i < 30; i++ {
		// Invalid bodies still count; they reach the limiter after auth.
		if c, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", []byte("junk")); c != 400 {
			t.Fatalf("%d: %d %s", i, c, b)
		}
	}
	req, _ := http.NewRequest("PUT", e.srv.URL+"/v1/bundles/alice/x/1.0.0", bytes.NewReader([]byte("junk")))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 429 || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("%d %v", resp.StatusCode, resp.Header)
	}
	// A different user is unaffected.
	e.user.id, e.user.login = 2, "bob"
	if c, _ := e.do(t, "PUT", "/v1/bundles/bob/x/1.0.0", []byte("junk")); c != 400 {
		t.Fatalf("bob %d", c)
	}
	e.user.id, e.user.login = 1, "alice"
	clk.t = clk.t.Add(time.Hour + time.Second)
	if c, _ := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", []byte("junk")); c != 400 {
		t.Fatalf("after window %d", c)
	}
}

func publishVersions(t *testing.T, e *env, vs ...string) map[string][]byte {
	out := map[string][]byte{}
	for _, v := range vs {
		out[v] = bundle(t, "x", v)
		if c, b := e.do(t, "PUT", "/v1/bundles/alice/x/"+v, out[v]); c != 201 {
			t.Fatalf("%s: %d %s", v, c, b)
		}
	}
	return out
}

type resolved struct {
	Version string `json:"version"`
	Digest  string `json:"digest"`
	Yanked  bool   `json:"yanked"`
	Warning string `json:"warning"`
	Error   string `json:"error"`
}

func (e *env) resolve(t *testing.T, rng string) (int, resolved) {
	c, b := e.do(t, "GET", "/v1/bundles/alice/x/resolve?range="+rng, nil)
	var r resolved
	json.Unmarshal(b, &r)
	return c, r
}

func TestYankAndResolve(t *testing.T) {
	e, _ := setupCfg(t, Config{})
	// Publish out of semver order; created_at order must not matter.
	tbs := publishVersions(t, e, "1.9.0", "1.10.0-rc.1", "1.0.0", "1.1.0")
	if c, r := e.resolve(t, "latest"); c != 200 || r.Version != "1.9.0" {
		t.Fatalf("prerelease must lose to release: %d %+v", c, r)
	}
	publishVersions(t, e, "1.10.0")
	if c, r := e.resolve(t, "latest"); c != 200 || r.Version != "1.10.0" {
		t.Fatalf("%d %+v", c, r)
	}
	if c, b := e.do(t, "POST", "/v1/bundles/alice/x/1.10.0/yank", nil); c != 200 {
		t.Fatalf("yank %d %s", c, b)
	}
	if c, r := e.resolve(t, "latest"); r.Version != "1.9.0" || c != 200 || r.Warning != "" {
		t.Fatalf("%d %+v", c, r)
	}
	// Exact pin of the yanked version still resolves with a warning and downloads.
	c, r := e.resolve(t, "1.10.0")
	if c != 200 || r.Version != "1.10.0" || r.Warning != "yanked" || !r.Yanked {
		t.Fatalf("%d %+v", c, r)
	}
	if c, _ := e.do(t, "GET", "/v1/bundles/alice/x/1.10.0/download", nil); c != 200 {
		t.Fatalf("download %d", c)
	}
	_ = tbs
	// Listing marks it.
	_, b := e.do(t, "GET", "/v1/bundles/alice/x", nil)
	var vs []struct {
		Version string
		Yanked  bool
	}
	json.Unmarshal(b, &vs)
	n := 0
	for _, v := range vs {
		if v.Yanked {
			n++
			if v.Version != "1.10.0" {
				t.Fatalf("wrong yanked %s", v.Version)
			}
		}
	}
	if n != 1 {
		t.Fatalf("yanked count %d", n)
	}
	// Un-yank.
	if c, _ := e.do(t, "DELETE", "/v1/bundles/alice/x/1.10.0/yank", nil); c != 200 {
		t.Fatal(c)
	}
	if _, r := e.resolve(t, "latest"); r.Version != "1.10.0" {
		t.Fatalf("%+v", r)
	}
	if c, r := e.resolve(t, "9.9.9"); c != 404 {
		t.Fatalf("%d %+v", c, r)
	}
}

func TestYank_1_1_0_FallsBackTo_1_0_0(t *testing.T) {
	e, _ := setupCfg(t, Config{})
	publishVersions(t, e, "1.0.0", "1.1.0")
	e.do(t, "POST", "/v1/bundles/alice/x/1.1.0/yank", nil)
	if _, r := e.resolve(t, "latest"); r.Version != "1.0.0" {
		t.Fatalf("%+v", r)
	}
	if c, r := e.resolve(t, "1.1.0"); c != 200 || r.Warning != "yanked" {
		t.Fatalf("%d %+v", c, r)
	}
}

func TestAllYankedLatest404(t *testing.T) {
	e, _ := setupCfg(t, Config{})
	publishVersions(t, e, "1.0.0")
	e.do(t, "POST", "/v1/bundles/alice/x/1.0.0/yank", nil)
	c, r := e.resolve(t, "latest")
	if c != 404 || r.Error == "" {
		t.Fatalf("%d %+v", c, r)
	}
	if c, _ := e.do(t, "GET", "/v1/bundles/alice/nope/resolve?range=latest", nil); c != 404 {
		t.Fatalf("unknown bundle %d", c)
	}
}

func TestYankAuth(t *testing.T) {
	e, _ := setupCfg(t, Config{})
	publishVersions(t, e, "1.0.0")
	e.user.id, e.user.login = 2, "bob"
	for _, m := range []string{"POST", "DELETE"} {
		if c, _ := e.do(t, m, "/v1/bundles/alice/x/1.0.0/yank", nil); c != 403 {
			t.Fatalf("%s non-owner %d", m, c)
		}
	}
	e.user.ok = false
	for _, m := range []string{"POST", "DELETE"} {
		if c, _ := e.do(t, m, "/v1/bundles/alice/x/1.0.0/yank", nil); c != 401 {
			t.Fatalf("%s unauth %d", m, c)
		}
	}
	e.user.id, e.user.login, e.user.ok = 1, "alice", true
	if c, _ := e.do(t, "POST", "/v1/bundles/alice/x/7.0.0/yank", nil); c != 404 {
		t.Fatalf("unknown version %d", c)
	}
	// Still downloadable and not yanked after the rejected attempts.
	_, b := e.do(t, "GET", "/v1/bundles/alice/x", nil)
	if bytes.Contains(b, []byte(`"yanked":true`)) {
		t.Fatal("yanked by non-owner")
	}
}

func TestTildeOwner404(t *testing.T) {
	e, _ := setupCfg(t, Config{})
	publishVersions(t, e, "1.0.0")
	e.user.id = 2 // alice's login moves to id 2; id 1 is tombstoned as "~1"
	e.do(t, "PUT", "/v1/bundles/alice/x/2.0.0", bundle(t, "x", "2.0.0"))
	for _, p := range []string{"/v1/bundles/~1/x", "/v1/bundles/%7E1/x", "/v1/bundles/~1/x/1.0.0/download", "/v1/bundles/~1/x/resolve?range=latest"} {
		if c, _ := e.do(t, "GET", p, nil); c != 404 {
			t.Errorf("%s: %d", p, c)
		}
	}
	e.user.login = "~1"
	if c, _ := e.do(t, "POST", "/v1/bundles/~1/x/1.0.0/yank", nil); c != 404 {
		t.Errorf("yank tilde: %d", c)
	}
	if c, _ := e.do(t, "PUT", "/v1/bundles/~1/x/1.0.0", nil); c != 404 {
		t.Errorf("put tilde: %d", c)
	}
}

func TestAuthRoutesLimitedPerIP(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	for _, trust := range []bool{false, true} {
		l := NewLimiter(2, time.Minute, nil)
		h := LimitByIP(l, trust, ok)
		do := func(remote, xff string) int {
			r := httptest.NewRequest("POST", "/v1/auth/device", nil)
			r.RemoteAddr = remote
			if xff != "" {
				r.Header.Set("X-Forwarded-For", xff)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			return w.Code
		}
		do("1.1.1.1:1", "")
		do("1.1.1.1:2", "")
		if got := do("1.1.1.1:3", ""); got != 429 {
			t.Fatalf("trust=%v same IP: %d", trust, got)
		}
		// Rotating X-Forwarded-For must not evade the limit unless trusted.
		got := do("1.1.1.1:4", "6.6.6.6")
		if !trust && got != 429 {
			t.Fatalf("XFF honoured by default: %d", got)
		}
		if trust && got != 200 {
			t.Fatalf("trusted proxy XFF ignored: %d", got)
		}
		if do("2.2.2.2:1", "") != 200 {
			t.Fatal("other IP limited")
		}
	}
}
