package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/MasonD-007/capm/backend/internal/store"
)

// readOnlyOwnerRoutes are the registered routes that name an {owner} but act
// as nobody: reading, resolving and downloading bundles, and anonymous
// reports. Every OTHER route with {owner} (outside /v1/admin/, which has its
// own gate) writes as the caller and must decide "may this caller write under
// that owner" through authorizeOwner. A newly registered route is therefore
// treated as owner-gated until its author lists it here deliberately.
var readOnlyOwnerRoutes = map[string]bool{
	"GET /v1/bundles/{owner}/{name}":                     true,
	"GET /v1/bundles/{owner}/{name}/{version}":           true,
	"GET /v1/bundles/{owner}/{name}/{version}/download":  true,
	"GET /v1/bundles/{owner}/{name}/{version}/signature": true,
	"GET /v1/bundles/{owner}/{name}/resolve":             true,
	"POST /v1/bundles/{owner}/{name}/report":             true,
}

func TestEveryOwnerGatedRouteGoesThroughAuthorizeOwner(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	s.UpsertUser(2, "bob")
	var mu sync.Mutex
	var heard []string
	a := New(s, func(r *http.Request) (int64, string, bool) { return 1, "alice", true })
	a.authzHook = func(p string) { mu.Lock(); heard = append(heard, p); mu.Unlock() }
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)

	gated := 0
	for _, route := range a.Routes() {
		method, pat, _ := strings.Cut(route, " ")
		if !strings.Contains(pat, "{owner}") || strings.HasPrefix(pat, "/v1/admin/") || readOnlyOwnerRoutes[route] {
			continue
		}
		gated++
		mu.Lock()
		heard = nil
		mu.Unlock()
		path := strings.NewReplacer("{owner}", "bob", "{name}", "x", "{version}", "1.0.0").Replace(pat)
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(nil))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		mu.Lock()
		got := append([]string(nil), heard...)
		mu.Unlock()
		if len(got) != 1 || got[0] != route {
			t.Errorf("%s: authorizeOwner calls = %v (response %d)", route, got, resp.StatusCode)
		}
		// alice may not write under bob (a user); the single function says so.
		if resp.StatusCode != 403 {
			t.Errorf("%s: a stranger got %d, want 403", route, resp.StatusCode)
		}
	}
	// publish, signature upload, yank and un-yank today.
	if gated != 4 {
		t.Fatalf("%d owner-gated routes found, expected 4 (publish, signature upload, yank, un-yank); update this test if a route was added deliberately", gated)
	}
}

// Owner-gated handlers must not compare the URL owner with the caller's login
// themselves: that is exactly the logic that has to live in one place.
func TestNoHandlerComparesTheOwnerPathValueDirectly(t *testing.T) {
	// A behavioural stand-in for a source check: an organisation member whose
	// record is fresh is allowed by authorizeOwner on every gated route, which
	// would be impossible for a handler comparing logins itself.
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	s.UpsertUser(1, "alice")
	if err := s.ReplaceOrgMemberships(1, []store.OrgRecord{{OrgID: 77, Login: "acme", Role: store.RoleAdmin}}); err != nil {
		t.Fatal(err)
	}
	a := New(s, func(r *http.Request) (int64, string, bool) { return 1, "alice", true })
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	do := func(method, path string, body []byte) int {
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if c := do("PUT", "/v1/bundles/acme/x/1.0.0", bundle(t, "x", "1.0.0")); c != 201 {
		t.Fatalf("publish: %d", c)
	}
	sig := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","verificationMaterial":{},"messageSignature":{}}`)
	req, _ := http.NewRequest("PUT", srv.URL+"/v1/bundles/acme/x/1.0.0/signature", bytes.NewReader(sig))
	req.Header.Set("Content-Type", "application/json")
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 201 {
		t.Fatalf("org member signature upload: %v %v", resp, err)
	}
	for _, m := range []string{"POST", "DELETE"} {
		if c := do(m, "/v1/bundles/acme/x/1.0.0/yank", nil); c != 200 {
			t.Fatalf("%s yank: %d", m, c)
		}
	}
}

func TestOrgShapesInListVersionsAndMetadata(t *testing.T) {
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	s.UpsertUser(1, "alice")
	if err := s.ReplaceOrgMemberships(1, []store.OrgRecord{{OrgID: 77, Login: "acme", Role: store.RoleAdmin}}); err != nil {
		t.Fatal(err)
	}
	a := New(s, func(r *http.Request) (int64, string, bool) { return 1, "alice", true })
	srv := httptest.NewServer(a.Handler())
	t.Cleanup(srv.Close)
	do := func(method, path string, body []byte) (int, []byte) {
		req, _ := http.NewRequest(method, srv.URL+path, bytes.NewReader(body))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var buf bytes.Buffer
		buf.ReadFrom(resp.Body)
		return resp.StatusCode, buf.Bytes()
	}
	if c, b := do("PUT", "/v1/bundles/acme/x/1.0.0", bundle(t, "x", "1.0.0")); c != 201 {
		t.Fatalf("%d %s", c, b)
	}
	if c, b := do("PUT", "/v1/bundles/alice/own/1.0.0", bundle(t, "own", "1.0.0")); c != 201 {
		t.Fatalf("%d %s", c, b)
	}

	var meta map[string]any
	c, b := do("GET", "/v1/bundles/acme/x/1.0.0", nil)
	if c != 200 || json.Unmarshal(b, &meta) != nil || meta["ownerKind"] != "org" || meta["publishedBy"] != "alice" {
		t.Fatalf("org metadata %d %s", c, b)
	}
	var vs []map[string]any
	c, b = do("GET", "/v1/bundles/acme/x", nil)
	if c != 200 || json.Unmarshal(b, &vs) != nil || vs[0]["publishedBy"] != "alice" || vs[0]["ownerKind"] != "org" {
		t.Fatalf("org versions %d %s", c, b)
	}
	// For a user's own namespace publishedBy equals the owner, so it is omitted.
	c, b = do("GET", "/v1/bundles/alice/own/1.0.0", nil)
	meta = nil
	if c != 200 || json.Unmarshal(b, &meta) != nil || meta["ownerKind"] != "user" {
		t.Fatalf("user metadata %d %s", c, b)
	}
	if _, has := meta["publishedBy"]; has {
		t.Fatalf("publishedBy shown for a user namespace: %s", b)
	}
	c, b = do("GET", "/v1/bundles/alice/own", nil)
	if strings.Contains(string(b), "publishedBy") {
		t.Fatalf("versions list shows publishedBy for a user namespace: %s", b)
	}
	// List items and resolve say what kind of owner it is.
	var list []map[string]any
	c, b = do("GET", "/v1/bundles", nil)
	if c != 200 || json.Unmarshal(b, &list) != nil || len(list) != 2 {
		t.Fatalf("%d %s", c, b)
	}
	kinds := map[string]any{}
	for _, it := range list {
		kinds[it["owner"].(string)] = it["ownerKind"]
	}
	if kinds["acme"] != "org" || kinds["alice"] != "user" {
		t.Fatalf("%v", kinds)
	}
	c, b = do("GET", "/v1/bundles/acme/x/resolve", nil)
	var res map[string]any
	if c != 200 || json.Unmarshal(b, &res) != nil || res["ownerKind"] != "org" || res["ownerId"] != float64(77) {
		t.Fatalf("resolve %d %s", c, b)
	}
}
