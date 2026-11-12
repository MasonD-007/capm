package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/MasonD-007/capm/backend/internal/store"
)

type quotaEnv struct {
	*env
	st *store.Store
}

// quotaSetup is adminEnv with a handle on the store and chosen default limits.
func quotaSetup(t *testing.T, lim store.Limits, cfg Config) *quotaEnv {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.SetLimits(lim)
	t.Cleanup(func() { s.Close() })
	e := &env{dir: dir}
	e.user = &struct {
		id    int64
		login string
		ok    bool
	}{1, "alice", true}
	cfg.IsAdmin = func(id int64) bool { return id == adminID }
	if cfg.Now == nil {
		cfg.Now = (&fakeClock{time.Unix(1_000_000, 0)}).now
	}
	a := NewWithConfig(s, func(r *http.Request) (int64, string, bool) { return e.user.id, e.user.login, e.user.ok }, cfg)
	e.srv = httptest.NewServer(a.Handler())
	t.Cleanup(e.srv.Close)
	return &quotaEnv{env: e, st: s}
}

func decode(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not a JSON object: %s", b)
	}
	return m
}

func TestUserBytesQuota413Body(t *testing.T) {
	b1, b2 := bundle(t, "x", "1.0.0"), bundle(t, "x", "1.1.0")
	e := quotaSetup(t, store.Limits{UserBytes: int64(len(b1))}, Config{})
	if c, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", b1); c != 201 {
		t.Fatalf("%d %s", c, b)
	}
	c, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.1.0", b2)
	if c != 413 {
		t.Fatalf("%d %s", c, b)
	}
	m := decode(t, b)
	if m["limit"] != "user_bytes" || m["used"] != float64(len(b1)) || m["max"] != float64(len(b1)) {
		t.Fatalf("%s", b)
	}
	msg, _ := m["error"].(string)
	if !strings.Contains(msg, "storage limit") || !strings.Contains(msg, "B") {
		t.Fatalf("message: %q", msg)
	}
	// Distinguishable from the oversized-upload 413, which keeps its message.
	if strings.Contains(msg, "bundle too large") {
		t.Fatalf("%q", msg)
	}
}

func TestOversizedUploadKeepsItsOwn413(t *testing.T) {
	e := quotaSetup(t, store.DefaultLimits(), Config{MaxBundleBytes: 1024})
	c, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", make([]byte, 2048))
	m := decode(t, b)
	if c != 413 || m["error"] != "bundle too large" || m["limit"] != nil {
		t.Fatalf("%d %s", c, b)
	}
}

func TestBundleCountAndVersionCountQuota413(t *testing.T) {
	e := quotaSetup(t, store.Limits{UserBundles: 1, BundleVersions: 2}, Config{})
	for _, v := range []string{"1.0.0", "1.1.0"} {
		if c, b := e.do(t, "PUT", "/v1/bundles/alice/x/"+v, bundle(t, "x", v)); c != 201 {
			t.Fatalf("%d %s", c, b)
		}
	}
	c, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.2.0", bundle(t, "x", "1.2.0"))
	m := decode(t, b)
	if c != 413 || m["limit"] != "bundle_versions" || m["used"] != float64(2) || m["max"] != float64(2) {
		t.Fatalf("%d %s", c, b)
	}
	c, b = e.do(t, "PUT", "/v1/bundles/alice/y/1.0.0", bundle(t, "y", "1.0.0"))
	m = decode(t, b)
	if c != 413 || m["limit"] != "user_bundles" || m["used"] != float64(1) || m["max"] != float64(1) {
		t.Fatalf("%d %s", c, b)
	}
}

func TestTotalLimit507DisclosesNoNumbers(t *testing.T) {
	b1 := bundle(t, "x", "1.0.0")
	e := quotaSetup(t, store.Limits{TotalBytes: int64(len(b1))}, Config{})
	if c, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", b1); c != 201 {
		t.Fatalf("%d %s", c, b)
	}
	e.user.id, e.user.login = 2, "bob"
	c, b := e.do(t, "PUT", "/v1/bundles/bob/y/1.0.0", bundle(t, "y", "1.0.0"))
	m := decode(t, b)
	if c != 507 || m["limit"] != "total_bytes" {
		t.Fatalf("%d %s", c, b)
	}
	if _, has := m["used"]; has {
		t.Fatalf("registry usage disclosed: %s", b)
	}
	if _, has := m["max"]; has {
		t.Fatalf("registry limit disclosed: %s", b)
	}
	msg, _ := m["error"].(string)
	if strings.ContainsAny(msg, "0123456789") || !strings.Contains(msg, "full") || !strings.Contains(msg, "operator has been alerted") {
		t.Fatalf("message: %q", msg)
	}
}

func TestDuplicateAndInvalidBeatQuota(t *testing.T) {
	e := quotaSetup(t, store.Limits{BundleVersions: 1, UserBundles: 1}, Config{})
	if c, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", bundle(t, "x", "1.0.0")); c != 201 {
		t.Fatalf("%d %s", c, b)
	}
	if c, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", bundle(t, "x", "1.0.0")); c != 409 {
		t.Fatalf("duplicate must be 409, got %d %s", c, b)
	}
	if c, b := e.do(t, "PUT", "/v1/bundles/alice/y/1.0.0", []byte("junk")); c != 400 {
		t.Fatalf("invalid must be 400, got %d %s", c, b)
	}
}

func TestQuotaRejectionLeavesNoBlob(t *testing.T) {
	e := quotaSetup(t, store.Limits{UserBundles: 1}, Config{})
	e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", bundle(t, "x", "1.0.0"))
	e.do(t, "PUT", "/v1/bundles/alice/y/1.0.0", bundle(t, "y", "1.0.0"))
	es, _ := os.ReadDir(e.dir + "/blobs")
	if len(es) != 1 {
		t.Fatalf("blobs: %v", es)
	}
}

// A quota rejection still counts against the hourly publish allowance. Handing
// it back would let a user parked at their limit upload 5 MiB bodies, each
// unpacked and checked, without bound.
func TestQuotaRejectionConsumesPublishAllowance(t *testing.T) {
	e := quotaSetup(t, store.Limits{UserBundles: 1}, Config{PublishPerHour: 3})
	e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", bundle(t, "x", "1.0.0")) // 1
	for i := 0; i < 2; i++ {                                             // 2, 3
		if c, b := e.do(t, "PUT", "/v1/bundles/alice/y/1.0.0", bundle(t, "y", "1.0.0")); c != 413 {
			t.Fatalf("%d %s", c, b)
		}
	}
	if c, _ := e.do(t, "PUT", "/v1/bundles/alice/y/1.0.0", bundle(t, "y", "1.0.0")); c != 429 {
		t.Fatalf("want 429 once rejections used the allowance, got %d", c)
	}
}

func TestAdminQuotaGetPutAudited(t *testing.T) {
	e := quotaSetup(t, store.Limits{UserBytes: 1000, UserBundles: 5, BundleVersions: 7}, Config{})
	e.asAlice()
	if c, _ := e.do(t, "GET", "/v1/admin/users/alice/quota", nil); c != 404 {
		t.Fatalf("non-admin must see 404, got %d", c)
	}
	if c, _ := e.do(t, "PUT", "/v1/admin/users/alice/quota", []byte(`{"maxBytes":1,"maxBundles":1}`)); c != 404 {
		t.Fatalf("non-admin PUT must see 404, got %d", c)
	}
	e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", bundle(t, "x", "1.0.0")) // makes alice a known user (413 or 201)
	e.st.UpsertUser(1, "alice")

	e.asAdmin()
	c, b := e.do(t, "GET", "/v1/admin/users/alice/quota", nil)
	m := decode(t, b)
	if c != 200 || m["id"] != float64(1) || m["maxBytes"] != float64(1000) || m["maxBundles"] != float64(5) ||
		m["maxBundleVersions"] != float64(7) || m["bytesOverridden"] != false || m["bundlesOverridden"] != false {
		t.Fatalf("%d %s", c, b)
	}

	c, b = e.do(t, "PUT", "/v1/admin/users/alice/quota", []byte(`{"maxBytes":5000,"maxBundles":null}`))
	m = decode(t, b)
	if c != 200 || m["maxBytes"] != float64(5000) || m["bytesOverridden"] != true || m["maxBundles"] != float64(5) || m["bundlesOverridden"] != false {
		t.Fatalf("%d %s", c, b)
	}
	// Numeric id works too, and null clears.
	c, b = e.do(t, "PUT", "/v1/admin/users/1/quota", []byte(`{"maxBytes":null,"maxBundles":null}`))
	m = decode(t, b)
	if c != 200 || m["bytesOverridden"] != false || m["maxBytes"] != float64(1000) {
		t.Fatalf("%d %s", c, b)
	}
	_, b = e.do(t, "GET", "/v1/admin/log", nil)
	if n := strings.Count(string(b), `"action":"set_quota"`); n != 2 {
		t.Fatalf("want 2 audit rows, got %d: %s", n, b)
	}
}

func TestAdminQuotaPutValidation(t *testing.T) {
	e := quotaSetup(t, store.DefaultLimits(), Config{})
	e.st.UpsertUser(1, "alice")
	e.asAdmin()
	for _, body := range []string{
		``, `junk`, `{}`, `{"maxBytes":1}`, `{"maxBundles":1}`, // both keys are required so a typo cannot clear an override
		`{"maxBytes":-1,"maxBundles":null}`, `{"maxBytes":"5","maxBundles":null}`, `{"maxBytes":1.5,"maxBundles":null}`,
		`{"maxBytes":null,"maxBundles":9999999999999999999}`,
	} {
		if c, b := e.do(t, "PUT", "/v1/admin/users/alice/quota", []byte(body)); c != 400 {
			t.Errorf("%q: %d %s", body, c, b)
		}
	}
	if c, _ := e.do(t, "PUT", "/v1/admin/users/nobody/quota", []byte(`{"maxBytes":1,"maxBundles":1}`)); c != 404 {
		t.Errorf("unknown login: %d", c)
	}
	if c, _ := e.do(t, "GET", "/v1/admin/users/nobody/quota", nil); c != 404 {
		t.Errorf("unknown login GET: %d", c)
	}
}

func TestOverrideTakesEffectOnPublish(t *testing.T) {
	b1 := bundle(t, "x", "1.0.0")
	e := quotaSetup(t, store.Limits{UserBytes: int64(len(b1)) - 1}, Config{})
	if c, _ := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", b1); c != 413 {
		t.Fatalf("expected quota rejection, got %d", c)
	}
	e.st.UpsertUser(1, "alice")
	e.asAdmin()
	if c, b := e.do(t, "PUT", "/v1/admin/users/alice/quota", []byte(`{"maxBytes":100000,"maxBundles":null}`)); c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	e.asAlice()
	if c, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", b1); c != 201 {
		t.Fatalf("%d %s", c, b)
	}
}

func TestAdminsAreSubjectToQuotas(t *testing.T) {
	b1 := bundle(t, "x", "1.0.0")
	e := quotaSetup(t, store.Limits{UserBytes: int64(len(b1)) - 1}, Config{})
	e.asAdmin()
	if c, b := e.do(t, "PUT", "/v1/bundles/root/x/1.0.0", b1); c != 413 {
		t.Fatalf("%d %s", c, b)
	}
}
