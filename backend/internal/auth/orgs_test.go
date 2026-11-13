package auth_test

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MasonD-007/capm/backend/internal/api"
	"github.com/MasonD-007/capm/backend/internal/auth"
	"github.com/MasonD-007/capm/backend/internal/store"
)

// gMem is one organisation as GitHub reports it for a user. perm is the org's
// default_repository_permission as returned by GET /orgs/{org} (nil = the
// field is absent from the reply, which is what a member without enough
// visibility gets).
type gMem struct {
	id          int64
	login, role string
	perm        *string
}

type gUser struct {
	id    int64
	login string
	mem   []gMem
}

// orgGitHub is a fake GitHub for the device flow, /user, the organisation
// membership routes and GET /user/<id>. Device codes are "dc-<name>"; the
// access token for <name> is "gho_<name>".
type orgGitHub struct {
	mu      sync.Mutex
	srv     *httptest.Server
	users   map[string]*gUser // by name
	forms   map[string]url.Values
	scopes  map[string]string // device code -> scope asked for at device start
	reqs    []string          // "METHOD /path?query" of every API (non-OAuth) request
	accts   map[int64][2]string
	nextDC  string
	pageSz  int
	failMem bool
	failOrg map[string]bool
	// foreignNext makes the first membership page link to another host.
	foreignNext string
	// grantScope overrides the scope reported with the access token.
	grantScope *string
	orgIDs     map[string]int64 // reply id of GET /orgs/<login> if different
}

func newOrgGitHub(t *testing.T) *orgGitHub {
	g := &orgGitHub{users: map[string]*gUser{}, forms: map[string]url.Values{}, scopes: map[string]string{},
		accts: map[int64][2]string{}, failOrg: map[string]bool{}, orgIDs: map[string]int64{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /login/device/code", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		g.mu.Lock()
		defer g.mu.Unlock()
		g.forms["device"] = r.Form
		g.scopes[g.nextDC] = r.Form.Get("scope")
		json.NewEncoder(w).Encode(map[string]any{"device_code": g.nextDC, "user_code": "ABCD-1234",
			"verification_uri": "https://github.com/login/device", "interval": 5, "expires_in": 900})
	})
	mux.HandleFunc("POST /login/oauth/access_token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		g.mu.Lock()
		defer g.mu.Unlock()
		g.forms["token"] = r.Form
		name := strings.TrimPrefix(r.Form.Get("device_code"), "dc-")
		if _, ok := g.users[name]; !ok {
			json.NewEncoder(w).Encode(map[string]string{"error": "bad_device_code"})
			return
		}
		scope := g.scopes[r.Form.Get("device_code")]
		if g.grantScope != nil {
			scope = *g.grantScope
		}
		json.NewEncoder(w).Encode(map[string]string{"access_token": "gho_" + name, "scope": scope, "token_type": "bearer"})
	})
	api := func(h func(w http.ResponseWriter, r *http.Request, u *gUser)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.reqs = append(g.reqs, r.Method+" "+r.URL.RequestURI())
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer gho_")
			u, ok := g.users[tok]
			if !ok {
				w.WriteHeader(401)
				return
			}
			h(w, r, u)
		}
	}
	mux.HandleFunc("GET /user", api(func(w http.ResponseWriter, r *http.Request, u *gUser) {
		json.NewEncoder(w).Encode(map[string]any{"id": u.id, "login": u.login})
	}))
	mux.HandleFunc("GET /user/memberships/orgs", api(func(w http.ResponseWriter, r *http.Request, u *gUser) {
		if g.failMem {
			http.Error(w, "boom", 500)
			return
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page < 1 {
			page = 1
		}
		size := g.pageSz
		if size == 0 {
			size = 100
		}
		lo, hi := (page-1)*size, page*size
		if lo > len(u.mem) {
			lo = len(u.mem)
		}
		if hi > len(u.mem) {
			hi = len(u.mem)
		}
		if hi < len(u.mem) {
			next := g.srv.URL + "/user/memberships/orgs?state=active&per_page=100&page=" + strconv.Itoa(page+1)
			if g.foreignNext != "" {
				next = g.foreignNext + "/user/memberships/orgs?page=2"
			}
			w.Header().Set("Link", `<`+next+`>; rel="next"`)
		}
		out := []map[string]any{}
		for _, m := range u.mem[lo:hi] {
			out = append(out, map[string]any{"state": "active", "role": m.role,
				"organization": map[string]any{"id": m.id, "login": m.login}})
		}
		json.NewEncoder(w).Encode(out)
	}))
	mux.HandleFunc("GET /orgs/{org}", api(func(w http.ResponseWriter, r *http.Request, u *gUser) {
		org := r.PathValue("org")
		if g.failOrg[org] {
			http.Error(w, "boom", 500)
			return
		}
		for _, m := range u.mem {
			if m.login == org {
				id := m.id
				if v, ok := g.orgIDs[org]; ok {
					id = v
				}
				body := map[string]any{"id": id, "login": m.login}
				if m.perm != nil {
					body["default_repository_permission"] = *m.perm
				}
				json.NewEncoder(w).Encode(body)
				return
			}
		}
		http.NotFound(w, r)
	}))
	mux.HandleFunc("GET /user/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		g.mu.Lock()
		acc, ok := g.accts[id]
		g.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"id": id, "login": acc[0], "type": acc[1]})
	})
	g.srv = httptest.NewServer(mux)
	t.Cleanup(g.srv.Close)
	return g
}

func (g *orgGitHub) addUser(name string, id int64, mem ...gMem) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.users[name] = &gUser{id: id, login: name, mem: mem}
}

func (g *orgGitHub) setMem(name string, mem ...gMem) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.users[name].mem = mem
}

func (g *orgGitHub) apiRequests() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.reqs...)
}

func sp(s string) *string { return &s }

type orgEnv struct {
	gh  *orgGitHub
	srv *httptest.Server
	st  *store.Store
	dir string
}

func setupOrgs(t *testing.T) *orgEnv {
	t.Helper()
	gh := newOrgGitHub(t)
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	svc := auth.New(st, auth.Config{ClientID: "cid", APIURL: gh.srv.URL, OAuthURL: gh.srv.URL, AdminIDs: []int64{42}})
	reg := api.NewWithConfig(st, svc.Authenticate, api.Config{IsAdmin: svc.IsAdmin, AuthDetail: svc.AuthenticateDetail})
	mux := http.NewServeMux()
	mux.Handle("/v1/auth/", svc.Handler())
	mux.Handle("/v1/", reg.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &orgEnv{gh: gh, srv: srv, st: st, dir: dir}
}

func (e *orgEnv) do(t *testing.T, method, path, token string, body []byte) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
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

// login runs the device flow for name. orgs mirrors `capm login --orgs`.
func (e *orgEnv) login(t *testing.T, name string, orgs bool) (string, map[string]any) {
	t.Helper()
	return e.loginBody(t, name, orgs, "")
}

// loginBody is login with extra JSON fields (without braces) sent in the
// token request.
func (e *orgEnv) loginBody(t *testing.T, name string, orgs bool, extra string) (string, map[string]any) {
	t.Helper()
	e.gh.mu.Lock()
	e.gh.nextDC = "dc-" + name
	e.gh.mu.Unlock()
	dbody := []byte(nil)
	if orgs {
		dbody = []byte(`{"orgs":true}`)
	}
	if code, b := e.do(t, "POST", "/v1/auth/device", "", dbody); code != 200 {
		t.Fatalf("device: %d %s", code, b)
	}
	tb := fmt.Sprintf(`{"device_code":"dc-%s"`, name)
	if orgs {
		tb += `,"orgs":true`
	}
	if extra != "" {
		tb += "," + extra
	}
	tb += "}"
	code, b := e.do(t, "POST", "/v1/auth/token", "", []byte(tb))
	if code != 200 {
		t.Fatalf("token: %d %s", code, b)
	}
	if strings.Contains(string(b), "gho_") {
		t.Fatal("github token leaked in the reply")
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil || out["token"] == "" {
		t.Fatalf("%s", b)
	}
	return out["token"].(string), out
}

func (e *orgEnv) roleRows(t *testing.T) string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(e.dir, "capm.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT m.user_id, u.login, m.role FROM org_members m JOIN users u ON u.id = m.org_id ORDER BY m.user_id, u.login`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var uid int64
		var l, r string
		rows.Scan(&uid, &l, &r)
		out = append(out, fmt.Sprintf("%d:%s:%s", uid, l, r))
	}
	return strings.Join(out, ",")
}

func (e *orgEnv) accounts(t *testing.T) string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(e.dir, "capm.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query(`SELECT id, login, kind FROM users ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id int64
		var l, k string
		rows.Scan(&id, &l, &k)
		out = append(out, fmt.Sprintf("%d:%s:%s", id, l, k))
	}
	return strings.Join(out, ",")
}

// age makes every org record older by d.
func (e *orgEnv) age(t *testing.T, d time.Duration) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(e.dir, "capm.db")+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`UPDATE org_members SET checked_at = checked_at - ?`, int64(d.Seconds())); err != nil {
		t.Fatal(err)
	}
}

const (
	alicePerm = "write"
)

// fixture: alice (42) owns acme, is a plain member of globex (base read),
// initech (base write), hooli (base permission not returned) and umbrella
// (base none). bob (43) belongs to nothing.
func (e *orgEnv) fixture() {
	e.gh.addUser("alice", 42,
		gMem{77, "acme", "admin", nil},
		gMem{78, "globex", "member", sp("read")},
		gMem{79, "initech", "member", sp("write")},
		gMem{80, "hooli", "member", nil},
		gMem{81, "umbrella", "member", sp("none")})
	e.gh.addUser("bob", 43)
	e.gh.addUser("carol", 44, gMem{77, "acme", "member", sp("read")})
}

func TestPlainLoginRequestsExactlyTodaysScopeAndTouchesNoOrgs(t *testing.T) {
	e := setupOrgs(t)
	e.fixture()
	_, out := e.login(t, "alice", false)
	form := e.gh.forms["device"]
	if _, has := form["scope"]; has || len(form) != 1 || form.Get("client_id") != "cid" {
		t.Fatalf("device request to GitHub = %v, want only client_id", form)
	}
	for _, r := range e.gh.apiRequests() {
		if !strings.HasPrefix(r, "GET /user") || strings.Contains(r, "memberships") || strings.Contains(r, "/orgs/") {
			t.Fatalf("plain login called %s", r)
		}
	}
	if _, has := out["orgs"]; has {
		t.Fatalf("plain login reply has orgs: %v", out)
	}
	if e.roleRows(t) != "" {
		t.Fatal("plain login recorded memberships")
	}
}

func TestPlainLoginIgnoresOrgsFlagWithoutTheScope(t *testing.T) {
	e := setupOrgs(t)
	e.fixture()
	// The token request says orgs, but the device flow was started without
	// the scope (so GitHub did not grant it): nothing is listed or recorded.
	e.gh.mu.Lock()
	e.gh.nextDC = "dc-alice"
	e.gh.mu.Unlock()
	e.do(t, "POST", "/v1/auth/device", "", nil)
	code, b := e.do(t, "POST", "/v1/auth/token", "", []byte(`{"device_code":"dc-alice","orgs":true}`))
	if code != 200 {
		t.Fatalf("%d %s", code, b)
	}
	if e.roleRows(t) != "" {
		t.Fatalf("recorded without read:org: %s", e.roleRows(t))
	}
	for _, r := range e.gh.apiRequests() {
		if strings.Contains(r, "memberships") {
			t.Fatalf("listed memberships without the scope: %s", r)
		}
	}
	var out struct{ Orgs struct{ Note string } }
	json.Unmarshal(b, &out)
	if !strings.Contains(out.Orgs.Note, "read:org") {
		t.Fatalf("no explanation: %s", b)
	}
}

func TestOrgsLoginRequestsReadOrgScope(t *testing.T) {
	e := setupOrgs(t)
	e.fixture()
	e.gh.mu.Lock()
	e.gh.nextDC = "dc-alice"
	e.gh.mu.Unlock()
	code, b := e.do(t, "POST", "/v1/auth/device", "", []byte(`{"orgs":true}`))
	if code != 200 {
		t.Fatalf("%d %s", code, b)
	}
	if got := e.gh.forms["device"].Get("scope"); got != "read:org" {
		t.Fatalf("scope = %q", got)
	}
	var out map[string]any
	json.Unmarshal(b, &out)
	if out["scope"] != "read:org" { // lets the CLI tell an old registry from a new one
		t.Fatalf("reply %v", out)
	}
	// Anything else in the device request is ignored.
	for _, body := range []string{`{"orgs":false}`, `{"scope":"repo"}`, `{"orgs":"yes"}`, `not json`} {
		e.do(t, "POST", "/v1/auth/device", "", []byte(body))
		if _, has := e.gh.forms["device"]["scope"]; has && body != `not json` {
			t.Fatalf("%s asked GitHub for a scope: %v", body, e.gh.forms["device"])
		}
	}
}

func TestOrgsLoginRecordsOnlyWhoMayPublish(t *testing.T) {
	e := setupOrgs(t)
	e.fixture()
	_, out := e.login(t, "alice", true)
	if got := e.roleRows(t); got != "42:acme:admin,42:initech:member" {
		t.Fatalf("records = %q", got)
	}
	// Only the orgs that qualify exist as accounts: no row for globex (base
	// read), hooli (permission not returned) or umbrella (none).
	if got := e.accounts(t); got != "42:alice:user,77:acme:org,79:initech:org" {
		t.Fatalf("accounts = %q", got)
	}
	o, _ := out["orgs"].(map[string]any)
	if o["complete"] != true {
		t.Fatalf("%v", out)
	}
	rec, _ := o["recorded"].([]any)
	if len(rec) != 2 {
		t.Fatalf("%v", out)
	}
	// What GitHub was asked: the membership list, then the base permission of
	// each plain member org (admins qualify without the second call).
	reqs := strings.Join(e.gh.apiRequests(), "\n")
	for _, want := range []string{"GET /user/memberships/orgs?state=active&per_page=100", "GET /orgs/globex", "GET /orgs/initech", "GET /orgs/hooli", "GET /orgs/umbrella"} {
		if !strings.Contains(reqs, want) {
			t.Errorf("missing request %q in\n%s", want, reqs)
		}
	}
	if strings.Contains(reqs, "/orgs/acme") {
		t.Errorf("owner role needs no base-permission lookup:\n%s", reqs)
	}
}

func TestExtraRequestParametersCannotCreateOrgsOrMemberships(t *testing.T) {
	e := setupOrgs(t)
	e.fixture()
	extra := `"org":"evil","orgs_list":[{"id":999,"login":"evil","role":"admin"}],"memberships":[{"org":"evil","role":"admin"}],"user":"alice","id":42,"login":"evil"`
	e.loginBody(t, "bob", true, extra)
	if e.roleRows(t) != "" {
		t.Fatalf("records = %q", e.roleRows(t))
	}
	if got := e.accounts(t); got != "43:bob:user" {
		t.Fatalf("accounts = %q", got)
	}
	// Bob is a member of nothing on GitHub, so he must not be able to publish
	// anywhere but his own namespace; and no `evil` row exists to publish to.
	e.st.UpsertOrg(77, "acme")
	tok, _ := e.login(t, "bob", true)
	if code, _ := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.0", tok, bundle(t, "x", "1.0.0")); code != 403 {
		t.Fatalf("%d", code)
	}
	if code, _ := e.do(t, "PUT", "/v1/bundles/evil/x/1.0.0", tok, bundle(t, "x", "1.0.0")); code != 403 {
		t.Fatalf("%d", code)
	}
}

func TestOnlyOrgsGitHubListsForTheUserAreRecorded(t *testing.T) {
	e := setupOrgs(t)
	e.fixture()
	// carol is a plain member of acme with base read: nothing is recorded and
	// acme's row is not created by her login.
	e.login(t, "carol", true)
	if e.roleRows(t) != "" || e.accounts(t) != "44:carol:user" {
		t.Fatalf("records %q accounts %q", e.roleRows(t), e.accounts(t))
	}
}

func orgBundleOwned(t *testing.T, e *orgEnv) (alice, bob string) {
	t.Helper()
	alice, _ = e.login(t, "alice", true)
	bob, _ = e.login(t, "bob", true)
	return
}

func TestOrgPublishAuthorisation(t *testing.T) {
	e := setupOrgs(t)
	e.fixture()
	alice, bob := orgBundleOwned(t, e)
	carol, _ := e.login(t, "carol", true)

	// An org admin can publish and yank; the version records who did it.
	if code, b := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.0", alice, bundle(t, "x", "1.0.0")); code != 201 {
		t.Fatalf("admin: %d %s", code, b)
	}
	// A member whose org base permission is write can too.
	if code, b := e.do(t, "PUT", "/v1/bundles/initech/y/1.0.0", alice, bundle(t, "y", "1.0.0")); code != 201 {
		t.Fatalf("member with write: %d %s", code, b)
	}
	// Members of orgs whose base permission is read, absent or none cannot.
	for _, org := range []string{"globex", "hooli", "umbrella"} {
		e.st.UpsertOrg(map[string]int64{"globex": 78, "hooli": 80, "umbrella": 81}[org], org)
		if code, _ := e.do(t, "PUT", "/v1/bundles/"+org+"/y/1.0.0", alice, bundle(t, "y", "1.0.0")); code != 403 {
			t.Errorf("%s: %d", org, code)
		}
	}
	// A non-member cannot publish or yank.
	for _, tok := range []string{bob, carol} {
		if code, b := e.do(t, "PUT", "/v1/bundles/acme/x/2.0.0", tok, bundle(t, "x", "2.0.0")); code != 403 {
			t.Errorf("non-member publish: %d %s", code, b)
		}
		if code, b := e.do(t, "POST", "/v1/bundles/acme/x/1.0.0/yank", tok, nil); code != 403 {
			t.Errorf("non-member yank: %d %s", code, b)
		}
		if code, b := e.do(t, "DELETE", "/v1/bundles/acme/x/1.0.0/yank", tok, nil); code != 403 {
			t.Errorf("non-member unyank: %d %s", code, b)
		}
	}
	// Yank and un-yank by a member.
	if code, b := e.do(t, "POST", "/v1/bundles/acme/x/1.0.0/yank", alice, nil); code != 200 {
		t.Fatalf("member yank: %d %s", code, b)
	}
	if code, b := e.do(t, "DELETE", "/v1/bundles/acme/x/1.0.0/yank", alice, nil); code != 200 {
		t.Fatalf("member unyank: %d %s", code, b)
	}
	vs, err := e.st.Versions("acme", "x")
	if err != nil || len(vs) != 1 || vs[0].Yanked || vs[0].PublishedBy != "alice" || vs[0].OwnerKind != "org" {
		t.Fatalf("%+v %v", vs, err)
	}
	// Quota and listing key on the org.
	if u, _ := e.st.Usage(77); u.Bundles != 1 {
		t.Fatalf("org usage %+v", u)
	}
	if u, _ := e.st.Usage(42); u.Bundles != 0 {
		t.Fatalf("publishing for the org was charged to the member: %+v", u)
	}
	// The member's own namespace still works, and the version there records no
	// separate publisher beyond the owner.
	if code, b := e.do(t, "PUT", "/v1/bundles/alice/own/1.0.0", alice, bundle(t, "own", "1.0.0")); code != 201 {
		t.Fatalf("own namespace: %d %s", code, b)
	}
	if vs, _ := e.st.Versions("alice", "own"); vs[0].PublishedBy != "" || vs[0].OwnerKind != "user" {
		t.Fatalf("%+v", vs[0])
	}
	// Someone else's personal namespace stays closed to org members.
	if code, _ := e.do(t, "PUT", "/v1/bundles/bob/x/1.0.0", alice, bundle(t, "x", "1.0.0")); code != 403 {
		t.Fatalf("%d", code)
	}
}

func TestStaleMembershipRecordCannotPublishOrYank(t *testing.T) {
	e := setupOrgs(t)
	e.fixture()
	alice, _ := e.login(t, "alice", true)
	if code, b := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.0", alice, bundle(t, "x", "1.0.0")); code != 201 {
		t.Fatalf("%d %s", code, b)
	}
	e.age(t, 23*time.Hour)
	if code, b := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.1", alice, bundle(t, "x", "1.0.1")); code != 201 {
		t.Fatalf("23h old record: %d %s", code, b)
	}
	e.age(t, 2*time.Hour) // now 25h old
	code, b := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.2", alice, bundle(t, "x", "1.0.2"))
	if code != 403 || !strings.Contains(string(b), "capm login --orgs") {
		t.Fatalf("stale publish: %d %s", code, b)
	}
	code, b = e.do(t, "POST", "/v1/bundles/acme/x/1.0.0/yank", alice, nil)
	if code != 403 || !strings.Contains(string(b), "capm login --orgs") {
		t.Fatalf("stale yank: %d %s", code, b)
	}
	// Logging in again refreshes it.
	alice, _ = e.login(t, "alice", true)
	if code, b := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.2", alice, bundle(t, "x", "1.0.2")); code != 201 {
		t.Fatalf("after relogin: %d %s", code, b)
	}
}

func TestRelogginWithOrgsAfterLeavingAnOrgRemovesTheRecord(t *testing.T) {
	e := setupOrgs(t)
	e.fixture()
	alice, _ := e.login(t, "alice", true)
	if code, b := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.0", alice, bundle(t, "x", "1.0.0")); code != 201 {
		t.Fatalf("%d %s", code, b)
	}
	// alice leaves acme (and keeps initech).
	e.gh.setMem("alice", gMem{79, "initech", "member", sp("write")})
	alice, _ = e.login(t, "alice", true)
	if got := e.roleRows(t); got != "42:initech:member" {
		t.Fatalf("records = %q", got)
	}
	if code, _ := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.1", alice, bundle(t, "x", "1.0.1")); code != 403 {
		t.Fatalf("after leaving: %d", code)
	}
	// A plain login does not touch the records.
	e.login(t, "alice", false)
	if got := e.roleRows(t); got != "42:initech:member" {
		t.Fatalf("plain login changed records: %q", got)
	}
	// A user with nothing left has no records at all.
	e.gh.setMem("alice")
	e.login(t, "alice", true)
	if got := e.roleRows(t); got != "" {
		t.Fatalf("records = %q", got)
	}
}

func TestBannedUserCannotPublishToTheirOrg(t *testing.T) {
	e := setupOrgs(t)
	e.fixture()
	alice, _ := e.login(t, "alice", true)
	if err := e.st.BanUser(1, 42, "bad"); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.0", alice, bundle(t, "x", "1.0.0")); code != 401 {
		t.Fatalf("banned member publish: %d", code)
	}
	if code, _ := e.do(t, "POST", "/v1/bundles/acme/x/1.0.0/yank", alice, nil); code != 401 {
		t.Fatalf("banned member yank: %d", code)
	}
	// A banned user cannot log in again to record memberships either.
	e.gh.mu.Lock()
	e.gh.nextDC = "dc-alice"
	e.gh.mu.Unlock()
	e.do(t, "POST", "/v1/auth/device", "", []byte(`{"orgs":true}`))
	if code, _ := e.do(t, "POST", "/v1/auth/token", "", []byte(`{"device_code":"dc-alice","orgs":true}`)); code != 403 {
		t.Fatalf("banned login: %d", code)
	}
}

func TestBannedOrgIsHiddenAndCannotBePublishedTo(t *testing.T) {
	e := setupOrgs(t)
	e.fixture()
	alice, _ := e.login(t, "alice", true)
	if code, b := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.0", alice, bundle(t, "x", "1.0.0")); code != 201 {
		t.Fatalf("%d %s", code, b)
	}
	if err := e.st.BanUser(1, 77, "org abuse"); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.do(t, "GET", "/v1/bundles/acme/x", "", nil); code != 404 {
		t.Fatalf("banned org's bundle visible: %d", code)
	}
	code, b := e.do(t, "GET", "/v1/bundles?owner=acme", "", nil)
	if code != 200 || strings.TrimSpace(string(b)) != "[]" {
		t.Fatalf("%d %s", code, b)
	}
	if code, _ := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.1", alice, bundle(t, "x", "1.0.1")); code != 403 {
		t.Fatalf("publish to banned org: %d", code)
	}
	if code, _ := e.do(t, "POST", "/v1/bundles/acme/x/1.0.0/yank", alice, nil); code != 403 {
		t.Fatalf("yank in banned org: %d", code)
	}
	// The member can still publish to their own namespace.
	if code, b := e.do(t, "PUT", "/v1/bundles/alice/own/1.0.0", alice, bundle(t, "own", "1.0.0")); code != 201 {
		t.Fatalf("%d %s", code, b)
	}
}

func TestListMyOrgs(t *testing.T) {
	e := setupOrgs(t)
	e.fixture()
	alice, _ := e.login(t, "alice", true)
	code, b := e.do(t, "GET", "/v1/auth/orgs", alice, nil)
	if code != 200 {
		t.Fatalf("%d %s", code, b)
	}
	var out []struct {
		Org       string    `json:"org"`
		Role      string    `json:"role"`
		ExpiresAt time.Time `json:"expiresAt"`
		Expired   bool      `json:"expired"`
	}
	if err := json.Unmarshal(b, &out); err != nil || len(out) != 2 || out[0].Org != "acme" || out[0].Role != "admin" ||
		out[1].Org != "initech" || out[1].Role != "member" || out[0].Expired {
		t.Fatalf("%s %v", b, err)
	}
	if d := time.Until(out[0].ExpiresAt); d < 23*time.Hour || d > 24*time.Hour+time.Minute {
		t.Fatalf("expiresAt in %v", d)
	}
	e.age(t, 25*time.Hour)
	_, b = e.do(t, "GET", "/v1/auth/orgs", alice, nil)
	json.Unmarshal(b, &out)
	if !out[0].Expired {
		t.Fatalf("%s", b)
	}
	// Others see only their own; no token, no answer.
	bob, _ := e.login(t, "bob", true)
	if _, b := e.do(t, "GET", "/v1/auth/orgs", bob, nil); strings.TrimSpace(string(b)) != "[]" {
		t.Fatalf("%s", b)
	}
	if code, _ := e.do(t, "GET", "/v1/auth/orgs", "", nil); code != 401 {
		t.Fatalf("%d", code)
	}
}

func TestOrgMembershipPaginationFollowsLinksUpToACap(t *testing.T) {
	e := setupOrgs(t)
	var mem []gMem
	for i := 0; i < 12; i++ {
		mem = append(mem, gMem{int64(100 + i), fmt.Sprintf("org%02d", i), "admin", nil})
	}
	e.gh.addUser("alice", 42, mem...)
	e.gh.pageSz = 1
	_, out := e.login(t, "alice", true)
	rows := strings.Split(e.roleRows(t), ",")
	if len(rows) != 10 {
		t.Fatalf("recorded %d orgs, want the 10-page cap: %v", len(rows), rows)
	}
	o := out["orgs"].(map[string]any)
	if o["complete"] != false || !strings.Contains(o["note"].(string), "not all") {
		t.Fatalf("user not told the list was cut short: %v", o)
	}
	n := 0
	for _, r := range e.gh.apiRequests() {
		if strings.Contains(r, "/user/memberships/orgs") {
			n++
		}
	}
	if n != 10 {
		t.Fatalf("%d membership page requests", n)
	}
	// Without the cap in play, everything is read.
	e.gh.pageSz = 5
	e.gh.reqs = nil
	_, out = e.login(t, "alice", true)
	if got := len(strings.Split(e.roleRows(t), ",")); got != 12 || out["orgs"].(map[string]any)["complete"] != true {
		t.Fatalf("%d recorded, %v", got, out)
	}
}

func TestMembershipLinkToAnotherHostIsNeverFollowed(t *testing.T) {
	e := setupOrgs(t)
	hit := false
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		t.Errorf("request to a foreign host: %s %v", r.URL, r.Header)
	}))
	defer evil.Close()
	e.gh.addUser("alice", 42, gMem{77, "acme", "admin", nil}, gMem{78, "globex", "admin", nil})
	e.gh.pageSz = 1
	e.gh.foreignNext = evil.URL
	_, out := e.login(t, "alice", true)
	if hit {
		t.Fatal("the access token was sent to another host")
	}
	o := out["orgs"].(map[string]any)
	if o["complete"] != false {
		t.Fatalf("%v", o)
	}
	// Whatever could not be listed safely is not recorded, and what was read
	// before the bad link is.
	if got := e.roleRows(t); got != "42:acme:admin" {
		t.Fatalf("records = %q", got)
	}
}

func TestMembershipListingFailureKeepsExistingRecordsAndFailsClosed(t *testing.T) {
	e := setupOrgs(t)
	e.fixture()
	e.login(t, "alice", true)
	before := e.roleRows(t)
	e.gh.failMem = true
	tok, out := e.login(t, "alice", true) // the login itself still works
	if tok == "" {
		t.Fatal("no token")
	}
	o := out["orgs"].(map[string]any)
	if o["complete"] != false || o["note"] == "" {
		t.Fatalf("%v", o)
	}
	if after := e.roleRows(t); after != before {
		t.Fatalf("a failed listing changed records: %q -> %q", before, after)
	}
	// With no records at all, a failed listing authorises nothing.
	e2 := setupOrgs(t)
	e2.fixture()
	e2.st.UpsertOrg(77, "acme")
	e2.gh.failMem = true
	t2, _ := e2.login(t, "alice", true)
	if e2.roleRows(t) != "" {
		t.Fatal("records after a failed listing")
	}
	if code, _ := e2.do(t, "PUT", "/v1/bundles/acme/x/1.0.0", t2, bundle(t, "x", "1.0.0")); code != 403 {
		t.Fatalf("%d", code)
	}
}

func TestBasePermissionLookupFailureOrMismatchMeansNotQualified(t *testing.T) {
	e := setupOrgs(t)
	e.gh.addUser("alice", 42,
		gMem{79, "initech", "member", sp("write")},
		gMem{82, "wayne", "member", sp("admin")},
		gMem{83, "stark", "member", sp("write")},
		gMem{84, "oscorp", "member", sp("Write")}, // not an exact value
		gMem{85, "lex", "member", sp("")})
	e.gh.failOrg["stark"] = true // GET /orgs/stark fails
	e.gh.orgIDs["wayne"] = 999   // the reply is for a different org id: not trusted
	_, out := e.login(t, "alice", true)
	if got := e.roleRows(t); got != "42:initech:member" {
		t.Fatalf("records = %q", got)
	}
	if out["orgs"].(map[string]any)["complete"] != false {
		t.Fatalf("a failed base-permission lookup must be reported: %v", out)
	}
}

func TestAnOrgIDRecordedAsAUserIsNeverConverted(t *testing.T) {
	e := setupOrgs(t)
	e.fixture()
	e.st.UpsertUser(77, "someone") // GitHub now says 77 is an org: account-type confusion
	e.login(t, "alice", true)
	if got := e.accounts(t); !strings.Contains(got, "77:someone:user") || strings.Contains(got, "acme") {
		t.Fatalf("accounts = %q", got)
	}
	if got := e.roleRows(t); got != "42:initech:member" {
		t.Fatalf("records = %q", got)
	}
}

func TestGitHubTokenIsNeverLogged(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(io.Discard)
	e := setupOrgs(t)
	e.fixture()
	e.gh.failMem = true
	e.login(t, "alice", true)
	e.gh.failMem = false
	e.gh.failOrg["globex"] = true
	e.login(t, "alice", true)
	if strings.Contains(buf.String(), "gho_") {
		t.Fatalf("GitHub access token in logs:\n%s", buf.String())
	}
}

func TestOrgOnlyWorksWithLoginHeldByTheOrg(t *testing.T) {
	// A tombstoned org is not addressable: renamed orgs resolve under the new
	// login only, and members must log in again to learn it.
	e := setupOrgs(t)
	e.fixture()
	alice, _ := e.login(t, "alice", true)
	e.do(t, "PUT", "/v1/bundles/acme/x/1.0.0", alice, bundle(t, "x", "1.0.0"))
	e.gh.setMem("alice", gMem{77, "acme-renamed", "admin", nil})
	alice, _ = e.login(t, "alice", true)
	if code, _ := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.1", alice, bundle(t, "x", "1.0.1")); code != 403 {
		t.Fatalf("old org login: %d", code)
	}
	if code, b := e.do(t, "PUT", "/v1/bundles/acme-renamed/x/1.0.1", alice, bundle(t, "x", "1.0.1")); code != 201 {
		t.Fatalf("new org login: %d %s", code, b)
	}
}

var _ = []any{api.ScopePublish, strconv.Itoa}
