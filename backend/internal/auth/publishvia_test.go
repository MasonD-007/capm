package auth_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/MasonD-007/capm/backend/internal/api"
	"github.com/MasonD-007/capm/backend/internal/store"
)

func ciToken(t *testing.T, e *oidcEnv) string {
	t.Helper()
	code, out, _ := e.exchange(t, e.jwt(t, nil))
	if code != 200 {
		t.Fatalf("exchange: %d %v", code, out)
	}
	return out["token"].(string)
}

func TestCIPublishRecordsProvenance(t *testing.T) {
	e := newOIDCEnv(t, 0)
	ci := ciToken(t, e)
	if code, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", ci, bundle(t, "x", "1.0.0")); code != 201 {
		t.Fatalf("%d %s", code, b)
	}
	// A normal (full) token publishes the next version.
	full := e.mint(t, "full-via", "", time.Time{})
	if code, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.1.0", full, bundle(t, "x", "1.1.0")); code != 201 {
		t.Fatalf("%d %s", code, b)
	}
	vs, err := e.st.Versions("alice", "x")
	if err != nil || len(vs) != 2 {
		t.Fatal(vs, err)
	}
	var rec map[string]string
	if err := json.Unmarshal([]byte(vs[0].PublishedVia), &rec); err != nil {
		t.Fatalf("published_via %q: %v", vs[0].PublishedVia, err)
	}
	want := map[string]string{"repository": "alice/x", "repository_id": "7001",
		"workflow_ref": "alice/x/.github/workflows/publish.yml@refs/heads/main",
		"sha":          "0123456789abcdef0123456789abcdef01234567", "run_id": "555"}
	if len(rec) != len(want) {
		t.Fatalf("record %v", rec)
	}
	for k, v := range want {
		if rec[k] != v {
			t.Fatalf("%s = %q, want %q", k, rec[k], v)
		}
	}
	if vs[1].PublishedVia != "" {
		t.Fatalf("full-token publish has provenance %q", vs[1].PublishedVia)
	}

	// The metadata endpoint and the versions list expose it, for CI versions only.
	code, b := e.do(t, "GET", "/v1/bundles/alice/x/1.0.0", "", nil)
	var meta map[string]any
	json.Unmarshal(b, &meta)
	pv, _ := meta["publishedVia"].(map[string]any)
	if code != 200 || pv["repository"] != "alice/x" || pv["workflowRef"] != want["workflow_ref"] || pv["sha"] != want["sha"] || len(pv) != 3 {
		t.Fatalf("metadata publishedVia: %d %s", code, b)
	}
	_, b = e.do(t, "GET", "/v1/bundles/alice/x/1.1.0", "", nil)
	if strings.Contains(string(b), "publishedVia") {
		t.Fatalf("metadata of a normal publish has publishedVia: %s", b)
	}
	_, b = e.do(t, "GET", "/v1/bundles/alice/x", "", nil)
	var list []map[string]any
	json.Unmarshal(b, &list)
	if len(list) != 2 {
		t.Fatalf("%s", b)
	}
	if _, has := list[0]["publishedVia"]; !has {
		t.Fatalf("versions list lacks publishedVia for the CI version: %s", b)
	}
	if _, has := list[1]["publishedVia"]; has {
		t.Fatalf("versions list has publishedVia for a normal publish: %s", b)
	}
	// The resolve endpoint and the bundle list are unchanged (no new fields).
	_, b = e.do(t, "GET", "/v1/bundles/alice/x/resolve", "", nil)
	if strings.Contains(string(b), "publishedVia") {
		t.Fatalf("resolve: %s", b)
	}
}

// The wording must stay factual: recorded provenance, never "verified".
func TestPublishedViaIsNotCalledVerified(t *testing.T) {
	e := newOIDCEnv(t, 0)
	ci := ciToken(t, e)
	e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", ci, bundle(t, "x", "1.0.0"))
	_, b := e.do(t, "GET", "/v1/bundles/alice/x/1.0.0", "", nil)
	var meta struct {
		PublishedVia map[string]string `json:"publishedVia"`
	}
	if err := json.Unmarshal(b, &meta); err != nil || len(meta.PublishedVia) != 3 {
		t.Fatalf("%v %s", err, b)
	}
	for k, v := range meta.PublishedVia {
		if strings.Contains(strings.ToLower(k+v), "verified") || strings.Contains(strings.ToLower(k+v), "trusted") {
			t.Fatalf("%s=%s", k, v)
		}
	}
}

func TestCITokenHitsQuotaAndRateLimitLikeAnyPublish(t *testing.T) {
	// Rate limit: 2 publishes per hour per user.
	e := newOIDCEnvCfg(t, 0, api.Config{PublishPerHour: 2})
	ci := ciToken(t, e)
	for i, want := range []int{201, 201, 429} {
		v := []string{"1.0.0", "1.0.1", "1.0.2"}[i]
		if code, b := e.do(t, "PUT", "/v1/bundles/alice/x/"+v, ci, bundle(t, "x", v)); code != want {
			t.Fatalf("publish %d: %d %s, want %d", i, code, b, want)
		}
	}

	// Quota: one bundle name per user.
	e2 := newOIDCEnv(t, 0)
	e2.st.SetLimits(store.Limits{UserBundles: 1})
	ci2 := ciToken(t, e2)
	if code, b := e2.do(t, "PUT", "/v1/bundles/alice/one/1.0.0", ci2, bundle(t, "one", "1.0.0")); code != 201 {
		t.Fatalf("%d %s", code, b)
	}
	code, b := e2.do(t, "PUT", "/v1/bundles/alice/two/1.0.0", ci2, bundle(t, "two", "1.0.0"))
	if code != 413 || !strings.Contains(string(b), "user_bundles") {
		t.Fatalf("quota: %d %s", code, b)
	}
	// Duplicate versions and invalid bundles are refused as ever.
	if code, _ := e2.do(t, "PUT", "/v1/bundles/alice/one/1.0.0", ci2, bundle(t, "one", "1.0.0")); code != 409 {
		t.Fatalf("duplicate: %d", code)
	}
	if code, _ := e2.do(t, "PUT", "/v1/bundles/alice/one/1.0.1", ci2, []byte("not a bundle")); code != 400 {
		t.Fatalf("invalid: %d", code)
	}
}

// A banned owner's CI token stops working immediately (existing ban rule).
func TestBannedOwnersCITokenStopsWorking(t *testing.T) {
	e := newOIDCEnv(t, 0)
	ci := ciToken(t, e)
	if err := e.st.BanUser(1, 42, "bad"); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", ci, bundle(t, "x", "1.0.0")); code != 401 {
		t.Fatalf("%d", code)
	}
}
