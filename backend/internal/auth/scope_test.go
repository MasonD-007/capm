package auth_test

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MasonD-007/capm/backend/internal/api"
	"github.com/MasonD-007/capm/backend/internal/auth"
	"github.com/MasonD-007/capm/backend/internal/store"
)

const publishRoute = "PUT /v1/bundles/{owner}/{name}/{version}"

// scopeEnv wires the handlers exactly as cmd/main.go does, including the
// scope-aware AuthDetail hook, and makes alice (id 42) an admin so that a
// refused admin route is a 403 from the scope gate rather than the admin
// gate's 404.
type scopeEnv struct {
	*env
	svc *auth.Service
	reg *api.API
}

func setupScoped(t *testing.T, cfg api.Config) *scopeEnv {
	t.Helper()
	gh := newFakeGitHub(t)
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := auth.New(st, auth.Config{ClientID: "cid", APIURL: gh.srv.URL, OAuthURL: gh.srv.URL, AdminIDs: []int64{42}})
	cfg.IsAdmin = svc.IsAdmin
	cfg.AuthDetail = svc.AuthenticateDetail
	reg := api.NewWithConfig(st, svc.Authenticate, cfg)
	mux := http.NewServeMux()
	mux.Handle("/v1/auth/", svc.Handler())
	mux.Handle("/v1/", reg.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	if err := st.UpsertUser(42, "alice"); err != nil {
		t.Fatal(err)
	}
	return &scopeEnv{env: &env{gh: gh, srv: srv, dir: dir, st: st}, svc: svc, reg: reg}
}

// mint stores a token for alice with the given scope and expiry and returns
// the raw token.
func (e *scopeEnv) mint(t *testing.T, raw, scope string, exp time.Time) string {
	t.Helper()
	h := sha256.Sum256([]byte(raw))
	claims := ""
	if scope != "" {
		claims = `{"repository":"alice/x","repository_id":"7","workflow_ref":"alice/x/.github/workflows/p.yml@refs/heads/main","sha":"abc123","run_id":"99"}`
	}
	if err := e.st.CreateScopedToken(h[:], 42, "ci:alice/x", exp, scope, claims); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestScopedTokenPublishesOnlyUnderItsOwnLogin(t *testing.T) {
	e := setupScoped(t, api.Config{})
	tok := e.mint(t, "scoped-1", "publish", time.Now().Add(15*time.Minute))
	if code, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", tok, bundle(t, "x", "1.0.0")); code != 201 {
		t.Fatalf("own namespace: %d %s", code, b)
	}
	if code, _ := e.do(t, "PUT", "/v1/bundles/bob/x/1.0.0", tok, bundle(t, "x", "1.0.0")); code != 403 {
		t.Fatalf("other namespace: %d", code)
	}
}

func TestExpiredScopedTokenIs401(t *testing.T) {
	e := setupScoped(t, api.Config{})
	tok := e.mint(t, "scoped-2", "publish", time.Now().Add(-time.Minute))
	if code, _ := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", tok, bundle(t, "x", "1.0.0")); code != 401 {
		t.Fatalf("expired: %d", code)
	}
}

// The legacy Authenticate func (what AuthFunc was before scopes) must never
// treat a scoped token as a full one: anything still wired to it fails closed.
func TestLegacyAuthenticateRefusesScopedTokens(t *testing.T) {
	e := setupScoped(t, api.Config{})
	tok := e.mint(t, "scoped-3", "publish", time.Now().Add(time.Minute))
	full := e.mint(t, "full-3", "", time.Time{})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	if _, _, ok := e.svc.Authenticate(req); ok {
		t.Fatal("legacy Authenticate accepted a scoped token")
	}
	req.Header.Set("Authorization", "Bearer "+full)
	if id, login, ok := e.svc.Authenticate(req); !ok || id != 42 || login != "alice" {
		t.Fatalf("full token: %d %q %v", id, login, ok)
	}
}

// publicRoutes are the registered routes that never authenticate a caller
// (reading, resolving and downloading bundles, and anonymous reports). A
// scoped token has no business on any other route, so every route NOT listed
// here must answer a publish-scoped token with 403, and so must the publish
// route's siblings. A newly registered route that is not listed here is
// therefore treated as authenticated and must refuse scoped tokens; the test
// fails until its author decides, and if it needs auth the gate is already
// there.
var publicRoutes = map[string]bool{
	"GET /v1/bundles":                                   true,
	"GET /v1/bundles/{owner}/{name}":                    true,
	"GET /v1/bundles/{owner}/{name}/{version}":          true,
	"GET /v1/bundles/{owner}/{name}/{version}/download": true,
	"GET /v1/bundles/{owner}/{name}/resolve":            true,
	"POST /v1/bundles/{owner}/{name}/report":            true,
	"POST /v1/auth/device":                              true,
	"POST /v1/auth/token":                               true,
	"POST /v1/auth/oidc":                                true,
}

func TestScopedTokenIsRefusedOnEveryAuthenticatedRoute(t *testing.T) {
	e := setupScoped(t, api.Config{})
	tok := e.mint(t, "scoped-4", "publish", time.Now().Add(15*time.Minute))
	// A real bundle to act on, so routes that need one get past 404.
	full := e.mint(t, "full-4", "", time.Time{})
	if code, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", full, bundle(t, "x", "1.0.0")); code != 201 {
		t.Fatalf("seed: %d %s", code, b)
	}
	routes := append(e.reg.Routes(), e.svc.Routes()...)
	if len(routes) < 25 {
		t.Fatalf("only %d routes enumerated: %v", len(routes), routes)
	}
	repl := strings.NewReplacer("{owner}", "alice", "{name}", "x", "{version}", "1.0.0", "{id}", "1", "{user}", "alice")
	seenPublish, seenGated := false, 0
	for _, route := range routes {
		method, pat, _ := strings.Cut(route, " ")
		path := repl.Replace(pat)
		if route == publishRoute {
			seenPublish = true
			path = "/v1/bundles/alice/x/2.0.0"
		}
		var body []byte
		if method == "PUT" || method == "POST" {
			body = []byte(`{"reason":"x"}`)
		}
		if route == publishRoute {
			body = bundle(t, "x", "2.0.0")
		}
		code, resp := e.do(t, method, path, tok, body)
		switch {
		case route == publishRoute:
			if code != 201 {
				t.Errorf("%s: scoped token must publish, got %d %s", route, code, resp)
			}
		case publicRoutes[route]:
			if code == 403 || code == 401 {
				t.Errorf("%s: public route answered %d", route, code)
			}
		default:
			seenGated++
			if code != 403 || !strings.Contains(string(resp), "publish-scoped") {
				t.Errorf("%s: scoped token got %d %s, want 403 mentioning publish-scoped", route, code, resp)
			}
		}
	}
	if !seenPublish || seenGated < 15 {
		t.Fatalf("publish seen %v, gated routes %d", seenPublish, seenGated)
	}
	// The token is still alive afterwards (nothing above revoked it).
	if code, _ := e.do(t, "PUT", "/v1/bundles/alice/x/3.0.0", tok, bundle(t, "x", "3.0.0")); code != 201 {
		t.Fatalf("token was damaged by the sweep: %d", code)
	}
}

// The two packages each name the scope (auth mints it, api enforces it); they
// must never drift apart.
func TestScopeNamesAgree(t *testing.T) {
	if auth.ScopePublish != api.ScopePublish {
		t.Fatalf("auth %q != api %q", auth.ScopePublish, api.ScopePublish)
	}
}

// Every route a full token can use stays usable (the gate must not break
// existing behaviour).
func TestFullTokenStillUsesTokenRoutes(t *testing.T) {
	e := setupScoped(t, api.Config{})
	full := e.mint(t, "full-5", "", time.Time{})
	for _, p := range []string{"/v1/auth/me", "/v1/auth/tokens", "/v1/auth/usage"} {
		if code, b := e.do(t, "GET", p, full, nil); code != 200 {
			t.Errorf("%s: %d %s", p, code, b)
		}
	}
}
