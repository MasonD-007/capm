package auth_test

import (
	"bytes"
	"crypto/sha256"
	"io"
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
const signatureRoute = "PUT /v1/bundles/{owner}/{name}/{version}/signature"

// scopedAllowed is the complete set of route patterns a publish-scoped token
// may call. Adding to it is a deliberate security decision; the sweep below
// asserts that exactly these two answer a scoped token and every other
// authenticated route refuses it.
var scopedAllowed = map[string]bool{publishRoute: true, signatureRoute: true}

const sigJSON = `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{},"messageSignature":{}}`

// doJSON is e.do with a JSON content type (signature uploads need one).
func (e *env) doJSON(t *testing.T, method, path, token string, body []byte) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

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
	"GET /v1/bundles":                                    true,
	"GET /v1/bundles/{owner}/{name}":                     true,
	"GET /v1/bundles/{owner}/{name}/{version}":           true,
	"GET /v1/bundles/{owner}/{name}/{version}/download":  true,
	"GET /v1/bundles/{owner}/{name}/{version}/signature": true,
	"GET /v1/bundles/{owner}/{name}/resolve":             true,
	"POST /v1/bundles/{owner}/{name}/report":             true,
	"POST /v1/auth/device":                               true,
	"POST /v1/auth/token":                                true,
	"POST /v1/auth/oidc":                                 true,
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
	seenAllowed, seenGated := map[string]bool{}, 0
	for _, route := range routes {
		method, pat, _ := strings.Cut(route, " ")
		path := repl.Replace(pat)
		var body []byte
		if method == "PUT" || method == "POST" {
			body = []byte(`{"reason":"x"}`)
		}
		switch route {
		case publishRoute:
			path = "/v1/bundles/alice/x/2.0.0"
			body = bundle(t, "x", "2.0.0")
		case signatureRoute:
			body = []byte(sigJSON)
		}
		code, resp := e.doJSON(t, method, path, tok, body)
		switch {
		case scopedAllowed[route]:
			seenAllowed[route] = true
			if code != 201 {
				t.Errorf("%s: scoped token must be allowed, got %d %s", route, code, resp)
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
	// Precisely two patterns answer a scoped token, and both were exercised.
	if len(scopedAllowed) != 2 || len(seenAllowed) != 2 || seenGated < 15 {
		t.Fatalf("allowed patterns seen %v (of %v), gated routes %d", seenAllowed, scopedAllowed, seenGated)
	}
	// The token is still alive afterwards (nothing above revoked it).
	if code, _ := e.do(t, "PUT", "/v1/bundles/alice/x/3.0.0", tok, bundle(t, "x", "3.0.0")); code != 201 {
		t.Fatalf("token was damaged by the sweep: %d", code)
	}
}

// The two packages each name the scope (auth mints it, api enforces it); they
// must never drift apart.
func TestScopeNamesAgree(t *testing.T) {
	for _, other := range []string{api.ScopePublish, store.ScopePublish} {
		if auth.ScopePublish != other {
			t.Fatalf("auth %q, other %q", auth.ScopePublish, other)
		}
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

// A scoped token may sign only under the account it was minted for, and a
// token with any other scope is refused on the signature route.
func TestScopedTokenSignsOnlyUnderItsOwnLogin(t *testing.T) {
	e := setupScoped(t, api.Config{})
	tok := e.mint(t, "scoped-6", "publish", time.Now().Add(15*time.Minute))
	if code, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", tok, bundle(t, "x", "1.0.0")); code != 201 {
		t.Fatalf("publish: %d %s", code, b)
	}
	if code, b := e.doJSON(t, "PUT", "/v1/bundles/alice/x/1.0.0/signature", tok, []byte(sigJSON)); code != 201 {
		t.Fatalf("own namespace: %d %s", code, b)
	}
	if code, _ := e.doJSON(t, "PUT", "/v1/bundles/bob/x/1.0.0/signature", tok, []byte(sigJSON)); code != 403 {
		t.Fatalf("other namespace: %d", code)
	}
	other := e.mint(t, "scoped-7", "somethingelse", time.Now().Add(15*time.Minute))
	if code, _ := e.doJSON(t, "PUT", "/v1/bundles/alice/x/1.0.0/signature", other, []byte(sigJSON)); code != 403 {
		t.Fatalf("unknown scope: %d", code)
	}
	if code, _ := e.doJSON(t, "PUT", "/v1/bundles/alice/x/1.0.0/signature", "", []byte(sigJSON)); code != 401 {
		t.Fatalf("anonymous: %d", code)
	}
}
