package auth_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MasonD-007/capm/backend/internal/store"
)

// orgClaims is the ID token of a push to main in acme/x, an organisation
// repository, triggered by alice (a person with her own namespace).
func orgClaims(org string, ownerID int64) map[string]any {
	return map[string]any{
		"repository_owner_id": fmt.Sprint(ownerID), "repository_owner": org, "repository": org + "/x",
		"sub":          "repo:" + org + "/x:ref:refs/heads/main",
		"workflow_ref": org + "/x/.github/workflows/publish.yml@refs/heads/main", "job_workflow_ref": org + "/x/.github/workflows/publish.yml@refs/heads/main",
		"actor": "alice", "actor_id": "42",
	}
}

func orgCIToken(t *testing.T, e *oidcEnv, org string, id int64) string {
	t.Helper()
	code, out, _ := e.exchange(t, e.jwt(t, orgClaims(org, id)))
	if code != 200 {
		t.Fatalf("exchange for %s: %d %v", org, code, out)
	}
	return out["token"].(string)
}

func TestOIDCOrgOwnerMintsATokenBoundToTheOrg(t *testing.T) {
	e := newOIDCEnv(t, 0)
	code, out, _ := e.exchange(t, e.jwt(t, orgClaims("acme", 77)))
	if code != 200 || out["login"] != "acme" {
		t.Fatalf("%d %v", code, out)
	}
	tok := out["token"].(string)
	// The org row is created from the verified id and GitHub's login.
	a, err := e.st.AccountByLogin("acme")
	if err != nil || a.ID != 77 || a.Kind != store.KindOrg {
		t.Fatalf("%+v %v", a, err)
	}
	// The token belongs to the org's row (listing, revocation, the 20 cap).
	if list, _ := e.st.ListTokens(77, nil); len(list) != 1 || list[0].Name != "ci:acme/x" || list[0].Scope != "publish" {
		t.Fatalf("%+v", list)
	}
	if list, _ := e.st.ListTokens(42, nil); len(list) != 0 {
		t.Fatalf("the triggering actor owns the token: %+v", list)
	}
	h := sha256.Sum256([]byte(tok))
	stored, _ := e.st.LookupToken(h[:])
	if stored.UserID != 77 || stored.Kind != store.KindOrg {
		t.Fatalf("%+v", stored)
	}
	var claims map[string]string
	json.Unmarshal([]byte(stored.Claims), &claims)
	if claims["repository_owner_id"] != "77" || claims["actor"] != "alice" {
		t.Fatalf("%v", claims)
	}
	if code, b := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.0", tok, bundle(t, "x", "1.0.0")); code != 201 {
		t.Fatalf("publish: %d %s", code, b)
	}
	vs, err := e.st.Versions("acme", "x")
	if err != nil || len(vs) != 1 || vs[0].PublishedBy != "" || vs[0].OwnerKind != store.KindOrg ||
		!strings.Contains(vs[0].PublishedVia, `"repository":"acme/x"`) {
		t.Fatalf("%+v %v", vs, err)
	}
	// published_by stays NULL: no human acted.
	db, err := sql.Open("sqlite", "file:"+filepath.Join(e.dir, "capm.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var by sql.NullInt64
	if err := db.QueryRow(`SELECT published_by FROM versions WHERE owner_id = 77`).Scan(&by); err != nil || by.Valid {
		t.Fatalf("published_by = %v (%v), want NULL", by, err)
	}
	if u, _ := e.st.Usage(77); u.Bundles != 1 {
		t.Fatalf("org usage %+v", u)
	}
}

func TestCITokenForOrgACannotPublishAnywhereElse(t *testing.T) {
	e := newOIDCEnv(t, 0)
	e.mu.Lock()
	e.accounts[78] = [2]string{"globex", "Organization"}
	e.mu.Unlock()
	// The triggering actor (alice) is also an owner of globex and has a fresh
	// membership record: none of it matters to a CI token.
	e.st.UpsertUser(42, "alice")
	if err := e.st.ReplaceOrgMemberships(42, []store.OrgRecord{{OrgID: 78, Login: "globex", Role: store.RoleAdmin}, {OrgID: 77, Login: "acme", Role: store.RoleAdmin}}); err != nil {
		t.Fatal(err)
	}
	e.st.UpsertUser(43, "bob")
	tok := orgCIToken(t, e, "acme", 77)
	for _, owner := range []string{"globex", "alice", "bob", "nobody", "ACME-other"} {
		if code, b := e.do(t, "PUT", "/v1/bundles/"+owner+"/x/1.0.0", tok, bundle(t, "x", "1.0.0")); code != 403 {
			t.Errorf("acme CI token published under %s: %d %s", owner, code, b)
		}
	}
	if code, b := e.do(t, "PUT", "/v1/bundles/ACME/x/1.0.0", tok, bundle(t, "x", "1.0.0")); code != 201 {
		t.Fatalf("own org (case-insensitive): %d %s", code, b)
	}
	// Nothing leaked into the other namespaces.
	for _, o := range []string{"globex", "alice", "bob"} {
		if _, err := e.st.Versions(o, "x"); err == nil {
			t.Errorf("%s has a bundle", o)
		}
	}
	// A CI token cannot yank either.
	if code, _ := e.do(t, "POST", "/v1/bundles/acme/x/1.0.0/yank", tok, nil); code != 403 {
		t.Fatalf("yank with a CI token: %d", code)
	}
}

func TestCITokenForAUserRepoCannotPublishToAnOrg(t *testing.T) {
	e := newOIDCEnv(t, 0)
	// alice is an owner of acme with a fresh record: her interactive token may
	// publish there, her CI token (user repository) may not.
	e.st.UpsertUser(42, "alice")
	if err := e.st.ReplaceOrgMemberships(42, []store.OrgRecord{{OrgID: 77, Login: "acme", Role: store.RoleAdmin}}); err != nil {
		t.Fatal(err)
	}
	ci := ciToken(t, e)
	if code, b := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.0", ci, bundle(t, "x", "1.0.0")); code != 403 {
		t.Fatalf("user-repo CI token to an org: %d %s", code, b)
	}
	if code, b := e.do(t, "PUT", "/v1/bundles/bob/x/1.0.0", ci, bundle(t, "x", "1.0.0")); code != 403 {
		t.Fatalf("%d %s", code, b)
	}
	full := e.mint(t, "alice-full", "", time.Time{})
	if code, b := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.0", full, bundle(t, "x", "1.0.0")); code != 201 {
		t.Fatalf("interactive token (control): %d %s", code, b)
	}
}

func TestCITokenWhoseRecordedOwnerDisagreesIsRefused(t *testing.T) {
	e := newOIDCEnv(t, 0)
	e.st.UpsertOrg(77, "acme")
	h := sha256.Sum256([]byte("odd"))
	// Minted for the org's account but recorded as another owner's repository.
	if err := e.st.CreateScopedToken(h[:], 77, "ci", time.Now().Add(time.Minute), "publish", `{"repository":"alice/x","repository_owner_id":"42"}`); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.0", "odd", bundle(t, "x", "1.0.0")); code != 403 {
		t.Fatalf("%d", code)
	}
	h2 := sha256.Sum256([]byte("garbled"))
	if err := e.st.CreateScopedToken(h2[:], 77, "ci", time.Now().Add(time.Minute), "publish", `not json`); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.0", "garbled", bundle(t, "x", "1.0.0")); code != 403 {
		t.Fatalf("%d", code)
	}
}

func TestOrgCITokensAreRevokedThroughTheOrgsLogin(t *testing.T) {
	e := newOIDCEnv(t, 0)
	tok := orgCIToken(t, e, "acme", 77)
	e.st.UpsertUser(42, "alice")
	full := e.mint(t, "admin-full", "", time.Time{}) // alice (42) is the admin here
	code, b := e.do(t, "DELETE", "/v1/admin/users/acme/tokens", full, nil)
	if code != 200 || !strings.Contains(string(b), `"revoked":1`) {
		t.Fatalf("%d %s", code, b)
	}
	if code, _ := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.0", tok, bundle(t, "x", "1.0.0")); code != 401 {
		t.Fatalf("revoked org CI token: %d", code)
	}
	// By numeric id too.
	tok = orgCIToken(t, e, "acme", 77)
	if code, b := e.do(t, "DELETE", "/v1/admin/users/77/tokens", full, nil); code != 200 || !strings.Contains(string(b), `"revoked":1`) {
		t.Fatalf("%d %s", code, b)
	}
	_ = tok
}

func TestOrgQuotaAppliesToTheOrgAsOwnerAndAdminQuotaResolvesOrgs(t *testing.T) {
	e := newOIDCEnv(t, 0)
	tok := orgCIToken(t, e, "acme", 77)
	e.st.UpsertUser(42, "alice")
	full := e.mint(t, "admin-q", "", time.Time{})
	code, b := e.do(t, "PUT", "/v1/admin/users/acme/quota", full, []byte(`{"maxBytes":null,"maxBundles":1}`))
	if code != 200 || !strings.Contains(string(b), `"id":77`) || !strings.Contains(string(b), `"maxBundles":1`) {
		t.Fatalf("%d %s", code, b)
	}
	if code, b := e.do(t, "PUT", "/v1/bundles/acme/one/1.0.0", tok, bundle(t, "one", "1.0.0")); code != 201 {
		t.Fatalf("%d %s", code, b)
	}
	if code, b := e.do(t, "PUT", "/v1/bundles/acme/two/1.0.0", tok, bundle(t, "two", "1.0.0")); code != 413 || !strings.Contains(string(b), "user_bundles") {
		t.Fatalf("second bundle over the org's limit: %d %s", code, b)
	}
	// Alice's own quota is untouched.
	if u, _ := e.st.Usage(42); u.MaxBundles == 1 {
		t.Fatalf("quota override leaked to a user: %+v", u)
	}
	code, b = e.do(t, "GET", "/v1/admin/users/acme/quota", full, nil)
	if code != 200 || !strings.Contains(string(b), `"bundles":1`) {
		t.Fatalf("%d %s", code, b)
	}
}

func TestOIDCOrgTokenCapIsPerOrg(t *testing.T) {
	e := newOIDCEnv(t, 0)
	for i := 0; i < 20; i++ {
		if code, out, _ := e.exchange(t, e.jwt(t, orgClaims("acme", 77))); code != 200 {
			t.Fatalf("exchange %d: %d %v", i, code, out)
		}
	}
	if code, out, _ := e.exchange(t, e.jwt(t, orgClaims("acme", 77))); code != 429 {
		t.Fatalf("21st: %d %v", code, out)
	}
	// The actor's personal namespace and other accounts have their own count.
	if code, out, _ := e.exchange(t, e.jwt(t, nil)); code != 200 {
		t.Fatalf("user exchange: %d %v", code, out)
	}
}

func TestOIDCBannedOrgIsRefused(t *testing.T) {
	e := newOIDCEnv(t, 0)
	tok := orgCIToken(t, e, "acme", 77)
	if err := e.st.BanUser(1, 77, "abuse"); err != nil {
		t.Fatal(err)
	}
	code, out, _ := e.exchange(t, e.jwt(t, orgClaims("acme", 77)))
	if code != 403 || !strings.Contains(errOf(out), "banned") {
		t.Fatalf("%d %v", code, out)
	}
	if code, _ := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.0", tok, bundle(t, "x", "1.0.0")); code != 401 {
		t.Fatalf("existing token of a banned org: %d", code)
	}
}

func TestOIDCAccountIDNeverChangesKind(t *testing.T) {
	e := newOIDCEnv(t, 0)
	// 77 is recorded as a person; GitHub now says it is an organisation (or
	// the reverse for 42): refused, no token, nothing converted.
	e.st.UpsertUser(77, "weird")
	code, out, _ := e.exchange(t, e.jwt(t, orgClaims("acme", 77)))
	if code != 403 || out["token"] != nil {
		t.Fatalf("%d %v", code, out)
	}
	e.st.UpsertOrg(42, "alice")
	if code, out, _ := e.exchange(t, e.jwt(t, nil)); code != 403 || out["token"] != nil {
		t.Fatalf("%d %v", code, out)
	}
	if a, _ := e.st.AccountByLogin("weird"); a.Kind != store.KindUser {
		t.Fatalf("%+v", a)
	}
}

func TestOIDCOrgStillRefusesPullRequestsAndReplays(t *testing.T) {
	e := newOIDCEnv(t, 0)
	over := orgClaims("acme", 77)
	for k, v := range pullRequestClaims("pull_request_target") {
		over[k] = v
	}
	if code, out, _ := e.exchange(t, e.jwt(t, over)); code != 403 || !strings.Contains(errOf(out), "pull request") {
		t.Fatalf("%d %v", code, out)
	}
	tok := e.jwt(t, orgClaims("acme", 77))
	if code, _, _ := e.exchange(t, tok); code != 200 {
		t.Fatal(code)
	}
	if code, out, _ := e.exchange(t, tok); code != 401 || !strings.Contains(errOf(out), "replay") {
		t.Fatalf("%d %v", code, out)
	}
	// An organisation owner id that GitHub does not know fails closed.
	if code, _, _ := e.exchange(t, e.jwt(t, orgClaims("ghost", 999))); code != 503 {
		t.Fatalf("%d", code)
	}
	if _, err := e.st.AccountByLogin("ghost"); err == nil {
		t.Fatal("row created for an unverified org")
	}
}
