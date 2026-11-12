package auth_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/MasonD-007/capm/backend/internal/api"
	"github.com/MasonD-007/capm/backend/internal/auth"
	"github.com/MasonD-007/capm/backend/internal/store"
)

// setupTTL is setupAdmins with an explicit token lifetime (0 = never).
func setupTTL(t *testing.T, ttl time.Duration, admins []int64) *env {
	t.Helper()
	gh := newFakeGitHub(t)
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := auth.New(st, auth.Config{ClientID: "cid", APIURL: gh.srv.URL, OAuthURL: gh.srv.URL, AdminIDs: admins, TokenTTL: ttl})
	reg := api.NewWithConfig(st, svc.Authenticate, api.Config{IsAdmin: svc.IsAdmin})
	mux := http.NewServeMux()
	mux.Handle("/v1/auth/", svc.Handler())
	mux.Handle("/v1/", reg.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &env{gh: gh, srv: srv, dir: dir, st: st}
}

// sqlExec runs q on the server's database file (a second connection).
func (e *env) sqlExec(t *testing.T, q string, args ...any) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(e.dir, "capm.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(q, args...); err != nil {
		t.Fatal(err)
	}
}

func (e *env) loginNamed(t *testing.T, name string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"device_code": "dc1", "name": name})
	code, b := e.do(t, "POST", "/v1/auth/token", "", body)
	if code != 200 {
		t.Fatalf("token: %d %s", code, b)
	}
	var out struct{ Token string }
	json.Unmarshal(b, &out)
	return out.Token
}

type meBody struct {
	ID             int64  `json:"id"`
	Login          string `json:"login"`
	TokenID        int64  `json:"tokenId"`
	TokenExpiresAt string `json:"tokenExpiresAt"`
}

func (e *env) me(t *testing.T, tok string) (int, meBody, string) {
	t.Helper()
	code, b := e.do(t, "GET", "/v1/auth/me", tok, nil)
	var m meBody
	json.Unmarshal(b, &m)
	return code, m, string(b)
}

type tokenItem struct {
	ID         int64   `json:"id"`
	Name       string  `json:"name"`
	CreatedAt  string  `json:"createdAt"`
	LastUsedAt *string `json:"lastUsedAt"`
	ExpiresAt  *string `json:"expiresAt"`
	Current    bool    `json:"current"`
}

func (e *env) tokens(t *testing.T, tok string) []tokenItem {
	t.Helper()
	code, b := e.do(t, "GET", "/v1/auth/tokens", tok, nil)
	if code != 200 {
		t.Fatalf("list: %d %s", code, b)
	}
	var out []tokenItem
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return out
}

func TestTokenTTLDefaultsAndMe(t *testing.T) {
	e := setupTTL(t, 90*24*time.Hour, nil)
	tok := e.login(t)
	code, m, raw := e.me(t, tok)
	if code != 200 || m.Login != "alice" || m.ID != 42 || m.TokenID < 1 {
		t.Fatalf("%d %s", code, raw)
	}
	exp, err := time.Parse(time.RFC3339, m.TokenExpiresAt)
	if err != nil {
		t.Fatalf("tokenExpiresAt %q: %v", m.TokenExpiresAt, err)
	}
	if d := time.Until(exp); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Fatalf("expires in %v", d)
	}
}

func TestTTLZeroNeverExpires(t *testing.T) {
	e := setupTTL(t, 0, nil)
	tok := e.login(t)
	code, m, raw := e.me(t, tok)
	if code != 200 || m.TokenID < 1 {
		t.Fatalf("%d %s", code, raw)
	}
	if strings.Contains(raw, "tokenExpiresAt") {
		t.Fatalf("tokenExpiresAt must be omitted for a non-expiring token: %s", raw)
	}
	if l := e.tokens(t, tok); len(l) != 1 || l[0].ExpiresAt != nil {
		t.Fatalf("%+v", l)
	}
}

func TestExpiredAndRevokedLookLikeUnknown(t *testing.T) {
	e := setupTTL(t, 0, nil)
	expired, revoked := e.login(t), e.login(t)
	e.sqlExec(t, `UPDATE tokens SET expires_at = ? WHERE id = (SELECT MIN(id) FROM tokens)`, time.Now().Add(-time.Minute).Unix())
	e.sqlExec(t, `UPDATE tokens SET revoked_at = ? WHERE id = (SELECT MAX(id) FROM tokens)`, time.Now().Unix())
	_, want := e.do(t, "GET", "/v1/auth/me", "garbage", nil)
	for name, tok := range map[string]string{"expired": expired, "revoked": revoked} {
		code, b := e.do(t, "GET", "/v1/auth/me", tok, nil)
		if code != 401 || string(b) != string(want) {
			t.Errorf("%s: %d %q, want 401 %q", name, code, b, want)
		}
		if code, _ := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", tok, bundle(t, "x", "1.0.0")); code != 401 {
			t.Errorf("%s publish: %d", name, code)
		}
	}
}

func TestLastUsedUpdatedOnUse(t *testing.T) {
	e := setupTTL(t, 0, nil)
	tok := e.login(t)
	if l := e.tokens(t, tok); l[0].LastUsedAt == nil {
		t.Fatal("the listing request itself should have recorded last use")
	}
}

func TestListTokens(t *testing.T) {
	e := setupTTL(t, time.Hour, nil)
	a := e.loginNamed(t, "laptop")
	b := e.login(t)
	e.gh.set("", 7, "bob")
	bobTok := e.login(t)
	l := e.tokens(t, a)
	if len(l) != 2 || l[0].Name != "laptop" || !l[0].Current || l[1].Name != "" || l[1].Current {
		t.Fatalf("%+v", l)
	}
	if l[0].ID == l[1].ID || l[0].CreatedAt == "" || l[0].ExpiresAt == nil {
		t.Fatalf("%+v", l)
	}
	if bl := e.tokens(t, bobTok); len(bl) != 1 {
		t.Fatalf("bob sees %+v", bl)
	}
	_, raw := e.do(t, "GET", "/v1/auth/tokens", b, nil)
	for _, secret := range []string{a, b, bobTok, "hash"} {
		if strings.Contains(strings.ToLower(string(raw)), strings.ToLower(secret)) {
			t.Fatalf("listing leaks %q: %s", secret, raw)
		}
	}
}

func TestTokenRoutesNeedAuth(t *testing.T) {
	e := setupTTL(t, 0, nil)
	for _, r := range [][2]string{{"GET", "/v1/auth/tokens"}, {"DELETE", "/v1/auth/tokens/1"}, {"DELETE", "/v1/auth/tokens/current"}} {
		if code, _ := e.do(t, r[0], r[1], "", nil); code != 401 {
			t.Errorf("%v: %d", r, code)
		}
		if code, _ := e.do(t, r[0], r[1], "garbage", nil); code != 401 {
			t.Errorf("%v garbage: %d", r, code)
		}
	}
}

func TestRevokeByID(t *testing.T) {
	e := setupTTL(t, 0, nil)
	a, b := e.login(t), e.login(t)
	l := e.tokens(t, a)
	if code, body := e.do(t, "DELETE", "/v1/auth/tokens/"+itoa(l[1].ID), a, nil); code != 204 {
		t.Fatalf("%d %s", code, body)
	}
	if code, _, _ := e.me(t, b); code != 401 {
		t.Fatalf("revoked token still works: %d", code)
	}
	if code, _, _ := e.me(t, a); code != 200 {
		t.Fatalf("caller's token should still work: %d", code)
	}
	for _, id := range []string{itoa(l[1].ID), "999", "abc", "-1"} {
		if code, _ := e.do(t, "DELETE", "/v1/auth/tokens/"+id, a, nil); code != 404 {
			t.Errorf("id %s: %d, want 404", id, code)
		}
	}
}

func TestCannotRevokeAnotherUsersToken(t *testing.T) {
	e := setupTTL(t, 0, nil)
	alice := e.login(t)
	aliceID := e.tokens(t, alice)[0].ID
	e.gh.set("", 7, "bob")
	bob := e.login(t)
	if code, _ := e.do(t, "DELETE", "/v1/auth/tokens/"+itoa(aliceID), bob, nil); code != 404 {
		t.Fatalf("got %d, want 404", code)
	}
	if code, _, _ := e.me(t, alice); code != 200 {
		t.Fatal("alice's token was revoked by bob")
	}
}

func TestRevokeCurrent(t *testing.T) {
	e := setupTTL(t, 0, nil)
	a, b := e.login(t), e.login(t)
	if code, body := e.do(t, "DELETE", "/v1/auth/tokens/current", a, nil); code != 204 {
		t.Fatalf("%d %s", code, body)
	}
	if code, _, _ := e.me(t, a); code != 401 {
		t.Fatalf("next request after revoking current: %d", code)
	}
	if code, _, _ := e.me(t, b); code != 200 {
		t.Fatal("other token was revoked")
	}
}

func TestTokenName(t *testing.T) {
	e := setupTTL(t, 0, nil)
	cases := map[string]string{
		"laptop":                 "laptop",
		"  spaced  ":             "spaced",
		"evil\x1b[31m\nname\x00": "evil[31mname",
		strings.Repeat("a", 100): strings.Repeat("a", 64),
		strings.Repeat("é", 70):  strings.Repeat("é", 64),
		"":                       "",
		"bad\xffutf8":            "badutf8",
	}
	for in, want := range cases {
		tok := e.loginNamed(t, in)
		var got string
		for _, it := range e.tokens(t, tok) {
			if it.Current {
				got = it.Name
			}
		}
		if got != want {
			t.Errorf("name %q -> %q, want %q", in, got, want)
		}
	}
	// Older CLIs send no name at all.
	tok := e.login(t)
	for _, it := range e.tokens(t, tok) {
		if it.Current && it.Name != "" {
			t.Errorf("no name sent but got %q", it.Name)
		}
	}
}

func TestAdminRevokeUserTokens(t *testing.T) {
	e := setupTTL(t, 0, []int64{7})
	a1, a2 := e.login(t), e.login(t) // alice, id 42
	e.gh.set("", 8, "carol")
	carol := e.login(t)
	for _, tok := range []string{"", "garbage", a1} {
		if code, _ := e.do(t, "DELETE", "/v1/admin/users/alice/tokens", tok, nil); code != 404 {
			t.Fatalf("non-admin %q: %d, want 404", tok, code)
		}
	}
	if code, _, _ := e.me(t, a1); code != 200 {
		t.Fatal("tokens revoked by a non-admin request")
	}
	e.gh.set("", 7, "root")
	admin := e.login(t)
	code, b := e.do(t, "DELETE", "/v1/admin/users/alice/tokens", admin, nil)
	if code != 200 || !strings.Contains(string(b), `"revoked":2`) {
		t.Fatalf("%d %s", code, b)
	}
	for _, tok := range []string{a1, a2} {
		if code, _, _ := e.me(t, tok); code != 401 {
			t.Fatalf("token survived: %d", code)
		}
	}
	for _, tok := range []string{carol, admin} {
		if code, _, _ := e.me(t, tok); code != 200 {
			t.Fatalf("unrelated token revoked: %d", code)
		}
	}
	if code, _ := e.do(t, "DELETE", "/v1/admin/users/nobody/tokens", admin, nil); code != 404 {
		t.Fatalf("unknown user: %d", code)
	}
	if code, b := e.do(t, "DELETE", "/v1/admin/users/42/tokens", admin, nil); code != 200 {
		t.Fatalf("by id: %d %s", code, b)
	}
	code, b = e.do(t, "GET", "/v1/admin/log", admin, nil)
	if code != 200 || !strings.Contains(string(b), "revoke_tokens") || !strings.Contains(string(b), "user:42") {
		t.Fatalf("audit: %d %s", code, b)
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }
