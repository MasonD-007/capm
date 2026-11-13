package auth_test

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/MasonD-007/capm/backend/internal/api"
	"github.com/MasonD-007/capm/backend/internal/auth"
	"github.com/MasonD-007/capm/backend/internal/store"
)

const (
	oidcIssuer   = "https://token.actions.githubusercontent.com"
	oidcAudience = "https://capm.example.test"
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// oidcEnv is a full registry (auth + api, wired as cmd/main.go does) with a
// fake GitHub (JWKS is served separately, like the real issuer) and a fake
// GitHub API that knows account types.
type oidcEnv struct {
	*scopeEnv
	key    *rsa.PrivateKey
	kid    string
	jwks   *httptest.Server
	jwksOn atomic.Bool
	jwkDoc func() []map[string]any

	apiSrv   *httptest.Server
	mu       sync.Mutex
	accounts map[int64][2]string // id -> {login, type}
	apiHits  atomic.Int32
	apiDown  atomic.Bool
}

func newOIDCEnv(t *testing.T, ttl time.Duration) *oidcEnv {
	t.Helper()
	e := &oidcEnv{kid: "kid-1", accounts: map[int64][2]string{42: {"alice", "User"}, 77: {"acme", "Organization"}, 43: {"bob", "User"}}}
	var err error
	e.key, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e.jwksOn.Store(true)
	e.jwkDoc = func() []map[string]any { return []map[string]any{rsaJWK(e.kid, &e.key.PublicKey)} }
	e.jwks = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !e.jwksOn.Load() {
			http.Error(w, "down", 503)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": e.jwkDoc()})
	}))
	t.Cleanup(e.jwks.Close)
	e.apiSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.apiHits.Add(1)
		if e.apiDown.Load() {
			http.Error(w, "rate limited", 403)
			return
		}
		var id int64
		if _, err := fmt.Sscanf(r.URL.Path, "/user/%d", &id); err != nil {
			http.NotFound(w, r)
			return
		}
		e.mu.Lock()
		acc, ok := e.accounts[id]
		e.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": id, "login": acc[0], "type": acc[1]})
	}))
	t.Cleanup(e.apiSrv.Close)

	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := auth.New(st, auth.Config{ClientID: "cid", APIURL: e.apiSrv.URL, OAuthURL: e.apiSrv.URL, TokenTTL: ttl,
		OIDC: &auth.OIDCConfig{Issuer: oidcIssuer, JWKSURL: e.jwks.URL + "/.well-known/jwks", Audience: oidcAudience}})
	reg := api.NewWithConfig(st, svc.Authenticate, api.Config{IsAdmin: svc.IsAdmin, AuthDetail: svc.AuthenticateDetail})
	mux := http.NewServeMux()
	mux.Handle("/v1/auth/", svc.Handler())
	mux.Handle("/v1/", reg.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	e.scopeEnv = &scopeEnv{env: &env{srv: srv, dir: dir, st: st}, svc: svc, reg: reg}
	return e
}

func rsaJWK(kid string, pub *rsa.PublicKey) map[string]any {
	return map[string]any{"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
		"n": b64u(pub.N.Bytes()), "e": b64u(big.NewInt(int64(pub.E)).Bytes())}
}

func signJWT(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	in := b64u(hb) + "." + b64u(cb)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + b64u(sig)
}

var jtiCounter atomic.Int64

// pushClaims is what GitHub puts in the ID token of a `push` to main in
// alice/x, a user-owned repository.
func pushClaims(over map[string]any) map[string]any {
	now := time.Now().Unix()
	c := map[string]any{
		"jti": fmt.Sprintf("jti-%d-%d", now, jtiCounter.Add(1)),
		"sub": "repo:alice/x:ref:refs/heads/main",
		"aud": oidcAudience, "iss": oidcIssuer,
		"iat": now, "nbf": now - 300, "exp": now + 600,
		"ref": "refs/heads/main", "sha": "0123456789abcdef0123456789abcdef01234567",
		"repository": "alice/x", "repository_owner": "alice", "repository_owner_id": "42",
		"repository_id": "7001", "repository_visibility": "public",
		"run_id": "555", "run_number": "3", "run_attempt": "1",
		"actor": "alice", "actor_id": "42", "workflow": "publish",
		"head_ref": "", "base_ref": "", "event_name": "push", "ref_type": "branch", "ref_protected": "true",
		"workflow_ref":       "alice/x/.github/workflows/publish.yml@refs/heads/main",
		"workflow_sha":       "0123456789abcdef0123456789abcdef01234567",
		"job_workflow_ref":   "alice/x/.github/workflows/publish.yml@refs/heads/main",
		"job_workflow_sha":   "0123456789abcdef0123456789abcdef01234567",
		"runner_environment": "github-hosted",
	}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

// pullRequestClaims: a pull_request run (the ref is the PR merge ref and the
// sub says pull_request).
func pullRequestClaims(event string) map[string]any {
	c := map[string]any{"event_name": event, "ref": "refs/pull/5/merge", "head_ref": "feature", "base_ref": "main",
		"sub": "repo:alice/x:pull_request", "ref_type": "branch", "ref_protected": "false"}
	if event == "pull_request_target" {
		// For pull_request_target the ref and sub are the BASE branch's, so
		// the token looks exactly like a push to main: only event_name tells.
		c["ref"], c["sub"] = "refs/heads/main", "repo:alice/x:ref:refs/heads/main"
	}
	return c
}

func (e *oidcEnv) jwt(t *testing.T, over map[string]any) string {
	return signJWT(t, e.key, map[string]any{"alg": "RS256", "typ": "JWT", "kid": e.kid}, pushClaims(over))
}

func (e *oidcEnv) exchange(t *testing.T, tok string) (int, map[string]any, http.Header) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"token": tok})
	return e.exchangeRaw(t, body)
}

func (e *oidcEnv) exchangeRaw(t *testing.T, body []byte) (int, map[string]any, http.Header) {
	t.Helper()
	resp, err := http.Post(e.srv.URL+"/v1/auth/oidc", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]any{"raw": string(b)}
	}
	return resp.StatusCode, out, resp.Header
}

func errOf(m map[string]any) string { s, _ := m["error"].(string); return s }

func TestOIDCExchangeMintsShortLivedPublishToken(t *testing.T) {
	for _, ttl := range []time.Duration{90 * 24 * time.Hour, 0} { // TOKEN_TTL_DAYS must not matter
		e := newOIDCEnv(t, ttl)
		code, out, _ := e.exchange(t, e.jwt(t, nil))
		if code != 200 {
			t.Fatalf("%d %v", code, out)
		}
		tok, _ := out["token"].(string)
		if tok == "" || out["login"] != "alice" {
			t.Fatalf("%v", out)
		}
		exp, err := time.Parse(time.RFC3339, out["expiresAt"].(string))
		if d := time.Until(exp); err != nil || d < 14*time.Minute || d > 15*time.Minute+5*time.Second {
			t.Fatalf("expiresAt %v (%v from now), ttl cfg %v", out["expiresAt"], time.Until(exp), ttl)
		}
		// What is stored: scope, name, the recorded claims subset, expiry.
		list, _ := e.st.ListTokens(42, nil)
		if len(list) != 1 || list[0].Name != "ci:alice/x" || list[0].Scope != "publish" {
			t.Fatalf("%+v", list)
		}
		if d := time.Until(list[0].ExpiresAt); d < 14*time.Minute || d > 16*time.Minute {
			t.Fatalf("stored expiry %v", d)
		}
		h := sha256.Sum256([]byte(tok))
		stored, err := e.st.LookupToken(h[:])
		if err != nil || stored.Scope != "publish" {
			t.Fatalf("%+v %v", stored, err)
		}
		var claims map[string]string
		if err := json.Unmarshal([]byte(stored.Claims), &claims); err != nil {
			t.Fatal(err)
		}
		want := map[string]string{"repository": "alice/x", "repository_id": "7001", "repository_owner_id": "42",
			"workflow_ref": "alice/x/.github/workflows/publish.yml@refs/heads/main", "job_workflow_ref": "alice/x/.github/workflows/publish.yml@refs/heads/main",
			"ref": "refs/heads/main", "sha": "0123456789abcdef0123456789abcdef01234567", "run_id": "555",
			"event_name": "push", "actor": "alice", "actor_id": "42"}
		if fmt.Sprint(claims) != fmt.Sprint(want) {
			t.Fatalf("claims\n got %v\nwant %v", claims, want)
		}
		// The token publishes, and the user is the GitHub account.
		if code, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", tok, bundle(t, "x", "1.0.0")); code != 201 {
			t.Fatalf("publish: %d %s", code, b)
		}
		// Visible and revocable by the owner through a full token.
		full := e.mint(t, "owner-full", "", time.Time{})
		code, b := e.do(t, "GET", "/v1/auth/tokens", full, nil)
		if code != 200 || !strings.Contains(string(b), `"name":"ci:alice/x"`) || !strings.Contains(string(b), `"scope":"publish"`) {
			t.Fatalf("%d %s", code, b)
		}
		if code, _ := e.do(t, "DELETE", fmt.Sprintf("/v1/auth/tokens/%d", list[0].ID), full, nil); code != 204 {
			t.Fatal(code)
		}
		if code, _ := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.1", tok, bundle(t, "x", "1.0.1")); code != 401 {
			t.Fatalf("revoked token: %d", code)
		}
	}
}

func TestOIDCTokenNameIsTruncated(t *testing.T) {
	e := newOIDCEnv(t, 0)
	long := "alice/" + strings.Repeat("r", 120)
	if code, out, _ := e.exchange(t, e.jwt(t, map[string]any{"repository": long})); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	list, _ := e.st.ListTokens(42, nil)
	if len([]rune(list[0].Name)) > 64 || !strings.HasPrefix(list[0].Name, "ci:alice/rrr") {
		t.Fatalf("%q", list[0].Name)
	}
}

func TestOIDCRenameIsHandledLikeDeviceLogin(t *testing.T) {
	e := newOIDCEnv(t, 0)
	e.st.UpsertUser(42, "alice-old")
	if code, out, _ := e.exchange(t, e.jwt(t, nil)); code != 200 || out["login"] != "alice" {
		t.Fatalf("%d %v", code, out)
	}
	if id, err := e.st.UserIDByLogin("alice"); err != nil || id != 42 {
		t.Fatalf("%d %v", id, err)
	}
}

// failure table: every row must be refused with the stated status and a body
// naming the broad check, and must not create a token.
func TestOIDCRefusals(t *testing.T) {
	e := newOIDCEnv(t, 0)
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	now := time.Now().Unix()
	jws := func(h, c map[string]any, key *rsa.PrivateKey) string { return signJWT(t, key, h, c) }
	good := map[string]any{"alg": "RS256", "kid": e.kid}
	parts := strings.Split(e.jwt(t, nil), ".")

	noneHdr, _ := json.Marshal(map[string]any{"alg": "none", "kid": e.kid})
	noneBody, _ := json.Marshal(pushClaims(nil))
	hsHdr, _ := json.Marshal(map[string]any{"alg": "HS256", "kid": e.kid})

	cases := []struct {
		name string
		tok  string
		code int
		msg  string
	}{
		{"alg none empty signature", b64u(noneHdr) + "." + b64u(noneBody) + ".", 401, "signature"},
		{"alg HS256", b64u(hsHdr) + "." + b64u(noneBody) + "." + b64u([]byte("x")), 401, "signature"},
		{"alg ES256", jws(map[string]any{"alg": "ES256", "kid": e.kid}, pushClaims(nil), e.key), 401, "signature"},
		{"tampered payload", parts[0] + "." + b64u([]byte(strings.Replace(string(noneBody), `"42"`, `"43"`, 1))) + "." + parts[2], 401, "signature"},
		{"signed by another key", jws(good, pushClaims(nil), other), 401, "signature"},
		{"unknown kid", jws(map[string]any{"alg": "RS256", "kid": "nope"}, pushClaims(nil), e.key), 401, "signature"},
		{"missing kid", jws(map[string]any{"alg": "RS256"}, pushClaims(nil), e.key), 401, "signature"},
		{"short key", jws(map[string]any{"alg": "RS256", "kid": "small"}, pushClaims(nil), small), 401, "signature"},
		{"wrong issuer", jws(good, pushClaims(map[string]any{"iss": "https://evil.example"}), e.key), 401, "issuer"},
		{"wrong audience", jws(good, pushClaims(map[string]any{"aud": "https://other.example"}), e.key), 401, "audience"},
		{"aud array of two", jws(good, pushClaims(map[string]any{"aud": []string{oidcAudience, "https://other.example"}}), e.key), 401, "audience"},
		{"expired", jws(good, pushClaims(map[string]any{"exp": now - 600, "iat": now - 1200, "nbf": now - 1200}), e.key), 401, "expired"},
		{"not yet valid", jws(good, pushClaims(map[string]any{"nbf": now + 600}), e.key), 401, "not yet valid"},
		{"lifetime too long", jws(good, pushClaims(map[string]any{"exp": now + 7200}), e.key), 401, "lifetime"},
		{"missing jti", jws(good, pushClaims(map[string]any{"jti": nil}), e.key), 401, "claim"},
		{"missing owner id", jws(good, pushClaims(map[string]any{"repository_owner_id": nil}), e.key), 401, "claim"},
		{"non-numeric owner id", jws(good, pushClaims(map[string]any{"repository_owner_id": "4x2"}), e.key), 401, "claim"},
		{"numeric (not string) owner id", jws(good, pushClaims(map[string]any{"repository_owner_id": 42}), e.key), 401, "claim"},
		{"missing owner", jws(good, pushClaims(map[string]any{"repository_owner": nil}), e.key), 401, "claim"},
		{"repository of another owner", jws(good, pushClaims(map[string]any{"repository": "mallory/x"}), e.key), 401, "claim"},
		{"missing repository", jws(good, pushClaims(map[string]any{"repository": nil}), e.key), 401, "claim"},
		{"missing event_name", jws(good, pushClaims(map[string]any{"event_name": nil}), e.key), 401, "claim"},
		{"pull_request", jws(good, pushClaims(pullRequestClaims("pull_request")), e.key), 403, "pull request"},
		{"pull_request_target", jws(good, pushClaims(pullRequestClaims("pull_request_target")), e.key), 403, "pull request"},
		{"pull_request_review", jws(good, pushClaims(map[string]any{"event_name": "pull_request_review"}), e.key), 403, "pull request"},
		{"org owner", jws(good, pushClaims(map[string]any{"repository_owner_id": "77", "repository_owner": "acme", "repository": "acme/x"}), e.key), 403, "organisation namespaces are not supported yet"},
		{"unknown owner id", jws(good, pushClaims(map[string]any{"repository_owner_id": "999"}), e.key), 503, "GitHub"},
		{"malformed base64", "!!!!." + parts[1] + "." + parts[2], 401, "signature"},
		{"extra dots", e.jwt(t, nil) + ".x", 401, "signature"},
		{"two parts", parts[0] + "." + parts[1], 401, "signature"},
		{"not a jwt", "hello", 401, "signature"},
	}
	// "small" is in the JWKS but is too weak to be trusted.
	e.jwkDoc = func() []map[string]any {
		return []map[string]any{rsaJWK(e.kid, &e.key.PublicKey), rsaJWK("small", &small.PublicKey)}
	}
	for _, c := range cases {
		code, out, hdr := e.exchange(t, c.tok)
		if code != c.code || !strings.Contains(errOf(out), c.msg) {
			t.Errorf("%s: %d %v, want %d containing %q", c.name, code, out, c.code, c.msg)
		}
		if _, has := out["token"]; has {
			t.Errorf("%s: minted a token", c.name)
		}
		if c.code == 503 && hdr.Get("Retry-After") == "" {
			t.Errorf("%s: 503 without Retry-After", c.name)
		}
		if strings.Contains(errOf(out), parts[1]) || strings.Contains(errOf(out), "mallory") {
			t.Errorf("%s: error echoes token contents: %v", c.name, out)
		}
	}
	if n, _ := e.st.ListTokens(42, nil); len(n) != 0 {
		t.Fatalf("tokens created by refused exchanges: %+v", n)
	}
}

func TestOIDCOrgOwnerMessageIsExact(t *testing.T) {
	e := newOIDCEnv(t, 0)
	code, out, _ := e.exchange(t, e.jwt(t, map[string]any{"repository_owner_id": "77", "repository_owner": "acme", "repository": "acme/x"}))
	if code != 403 || errOf(out) != "organisation namespaces are not supported yet" {
		t.Fatalf("%d %v", code, out)
	}
}

func TestOIDCReplayIs401(t *testing.T) {
	e := newOIDCEnv(t, 0)
	tok := e.jwt(t, nil)
	if code, out, _ := e.exchange(t, tok); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	code, out, _ := e.exchange(t, tok)
	if code != 401 || !strings.Contains(errOf(out), "replay") {
		t.Fatalf("%d %v", code, out)
	}
	if n, _ := e.st.ListTokens(42, nil); len(n) != 1 {
		t.Fatalf("replay minted a second token: %d", len(n))
	}
}

func TestOIDCConcurrentReplayMintsOnce(t *testing.T) {
	e := newOIDCEnv(t, 0)
	tok := e.jwt(t, nil)
	var wg sync.WaitGroup
	var ok atomic.Int32
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if code, _, _ := e.exchange(t, tok); code == 200 {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d successful exchanges of one jti", ok.Load())
	}
}

func TestOIDCBannedOwnerIsRefused(t *testing.T) {
	e := newOIDCEnv(t, 0)
	if err := e.st.UpsertUser(42, "alice"); err != nil {
		t.Fatal(err)
	}
	if err := e.st.BanUser(1, 42, "bad"); err != nil {
		t.Fatal(err)
	}
	code, out, _ := e.exchange(t, e.jwt(t, nil))
	if code != 403 || !strings.Contains(errOf(out), "banned") {
		t.Fatalf("%d %v", code, out)
	}
}

func TestOIDCOversizedBody(t *testing.T) {
	e := newOIDCEnv(t, 0)
	body := []byte(`{"token":"` + strings.Repeat("a", 17<<10) + `"}`)
	code, out, _ := e.exchangeRaw(t, body)
	if code != 413 {
		t.Fatalf("%d %v", code, out)
	}
	for _, b := range []string{``, `not json`, `{}`, `{"token":""}`, `{"token":5}`, `[]`} {
		if code, _, _ := e.exchangeRaw(t, []byte(b)); code != 400 {
			t.Errorf("%q: %d", b, code)
		}
	}
}

func TestOIDCJWKSUnavailableFailsClosedWith503(t *testing.T) {
	e := newOIDCEnv(t, 0)
	e.jwksOn.Store(false)
	code, out, hdr := e.exchange(t, e.jwt(t, nil))
	if code != 503 || hdr.Get("Retry-After") == "" {
		t.Fatalf("%d %v %v", code, out, hdr)
	}
	if n, _ := e.st.ListTokens(42, nil); len(n) != 0 {
		t.Fatal("token minted while keys were unavailable")
	}
}

func TestOIDCJWKSWithOnlyNonRSAKeyIsRefused(t *testing.T) {
	e := newOIDCEnv(t, 0)
	e.jwkDoc = func() []map[string]any {
		return []map[string]any{{"kty": "EC", "kid": e.kid, "crv": "P-256", "use": "sig", "x": "AAAA", "y": "AAAA"}}
	}
	code, out, _ := e.exchange(t, e.jwt(t, nil))
	if code != 401 {
		t.Fatalf("%d %v", code, out)
	}
}

func TestOIDCOwnerLookupFailureFailsClosed(t *testing.T) {
	e := newOIDCEnv(t, 0)
	e.apiDown.Store(true)
	tok := e.jwt(t, nil)
	code, out, hdr := e.exchange(t, tok)
	if code != 503 || hdr.Get("Retry-After") == "" || !strings.Contains(errOf(out), "GitHub") {
		t.Fatalf("%d %v", code, out)
	}
	// The failure did not burn the token id: once GitHub answers, the same
	// ID token still exchanges.
	e.apiDown.Store(false)
	if code, out, _ := e.exchange(t, tok); code != 200 {
		t.Fatalf("retry after lookup failure: %d %v", code, out)
	}
}

func TestOIDCOwnerLookupIsCachedAndIdChecked(t *testing.T) {
	e := newOIDCEnv(t, 0)
	for i := 0; i < 3; i++ {
		if code, out, _ := e.exchange(t, e.jwt(t, nil)); code != 200 {
			t.Fatalf("%d %v", code, out)
		}
	}
	if n := e.apiHits.Load(); n != 1 {
		t.Fatalf("%d GitHub lookups for 3 exchanges by one owner, want 1 (cache)", n)
	}
}

func TestOIDCOwnerTypeMustBeExactlyUser(t *testing.T) {
	e := newOIDCEnv(t, 0)
	e.mu.Lock()
	e.accounts[50] = [2]string{"robot", "Bot"}
	e.accounts[51] = [2]string{"ghost", "user"} // wrong case is not "User"
	e.mu.Unlock()
	for _, id := range []string{"50", "51"} {
		code, out, _ := e.exchange(t, e.jwt(t, map[string]any{"repository_owner_id": id, "repository_owner": "x", "repository": "x/y"}))
		if code != 403 {
			t.Errorf("owner %s: %d %v", id, code, out)
		}
	}
}

func TestOIDCActiveCITokensAreCapped(t *testing.T) {
	e := newOIDCEnv(t, 0)
	var last int
	for i := 0; i < 30; i++ {
		last, _, _ = e.exchange(t, e.jwt(t, nil))
		if last != 200 {
			if i < 20 {
				t.Fatalf("refused after only %d tokens", i)
			}
			break
		}
	}
	if last != 429 {
		t.Fatalf("cap not enforced: last status %d", last)
	}
}

func TestOIDCDisabledIs404(t *testing.T) {
	st, _ := store.Open(t.TempDir())
	defer st.Close()
	svc := auth.New(st, auth.Config{ClientID: "cid"}) // no OIDC config
	srv := httptest.NewServer(svc.Handler())
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/v1/auth/oidc", "application/json", strings.NewReader(`{"token":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("%d", resp.StatusCode)
	}
}

// Every failure logs exactly one line with the reason and the unverified
// repository, truncated and sanitised, and never any part of the token.
func TestOIDCFailureLogLine(t *testing.T) {
	e := newOIDCEnv(t, 0)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(io.Discard)
	evil := "mallory/\x1b[31m" + strings.Repeat("z", 200) + "\nINJECTED"
	tok := signJWT(t, e.key, map[string]any{"alg": "RS256", "kid": e.kid}, pushClaims(map[string]any{"repository": evil, "aud": "https://other.example"}))
	e.exchange(t, tok)
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("%d log lines: %q", len(lines), buf.String())
	}
	l := lines[0]
	if !strings.Contains(l, "audience") || !strings.Contains(l, "mallory/") || strings.Contains(l, "\x1b") || strings.Contains(l, "INJECTED") || len(l) > 400 {
		t.Fatalf("log line %q", l)
	}
	for _, part := range strings.Split(tok, ".") {
		if len(part) > 20 && strings.Contains(l, part[:20]) {
			t.Fatalf("token material in log: %q", l)
		}
	}
}
