package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/MasonD-007/capm/backend/internal/store"
)

// A body with unusual whitespace and key order: it must come back byte for
// byte.
const sigBody = " \t{\n  \"verificationMaterial\" : {\"x\":[1, 2]},\r\n\"messageSignature\":{ \"messageDigest\":{} },  \"mediaType\":\"application/vnd.dev.sigstore.bundle.v0.3+json\"\n}\n"

type sigEnv struct {
	*env
	st *store.Store
}

func sigSetup(t *testing.T, cfg Config) *sigEnv {
	t.Helper()
	s, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	e := &env{}
	e.user = &struct {
		id    int64
		login string
		ok    bool
	}{1, "alice", true}
	cfg.IsAdmin = func(id int64) bool { return id == adminID }
	a := NewWithConfig(s, func(r *http.Request) (int64, string, bool) { return e.user.id, e.user.login, e.user.ok }, cfg)
	e.srv = httptest.NewServer(a.Handler())
	t.Cleanup(e.srv.Close)
	return &sigEnv{env: e, st: s}
}

func (e *sigEnv) req(t *testing.T, method, path, ctype string, body []byte) (int, http.Header, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

func (e *sigEnv) publish(t *testing.T, name string, versions ...string) {
	t.Helper()
	for _, v := range versions {
		if c, b := e.do(t, "PUT", "/v1/bundles/alice/"+name+"/"+v, bundle(t, name, v)); c != 201 {
			t.Fatalf("%d %s", c, b)
		}
	}
}

func (e *sigEnv) put(t *testing.T, path string, body string) (int, []byte) {
	c, _, b := e.req(t, "PUT", path, "application/json", []byte(body))
	return c, b
}

const sigPath = "/v1/bundles/alice/x/1.0.0/signature"

func TestSignatureRoundTripByteIdentical(t *testing.T) {
	e := sigSetup(t, Config{})
	e.publish(t, "x", "1.0.0")
	if c, _, _ := e.req(t, "GET", sigPath, "", nil); c != 404 {
		t.Fatalf("unsigned GET: %d", c)
	}
	c, b := e.put(t, sigPath, sigBody)
	if c != 201 || strings.TrimSpace(string(b)) != "{}" {
		t.Fatalf("PUT: %d %s", c, b)
	}
	c, h, b := e.req(t, "GET", sigPath, "", nil)
	if c != 200 || string(b) != sigBody || h.Get("Content-Type") != "application/json" {
		t.Fatalf("GET: %d %q %q", c, h.Get("Content-Type"), b)
	}
	// Write-once.
	if c, b := e.put(t, sigPath, sigBody); c != 409 {
		t.Fatalf("second PUT: %d %s", c, b)
	}
}

func TestSignatureGETNeedsNoAuthentication(t *testing.T) {
	e := sigSetup(t, Config{})
	e.publish(t, "x", "1.0.0")
	e.put(t, sigPath, sigBody)
	e.user.ok = false
	if c, _, b := e.req(t, "GET", sigPath, "", nil); c != 200 || string(b) != sigBody {
		t.Fatalf("%d %s", c, b)
	}
	if c, _ := e.put(t, "/v1/bundles/alice/x/1.0.0/signature", sigBody); c != 401 {
		t.Fatalf("anonymous PUT: %d", c)
	}
}

func TestSignaturePUTRefusals(t *testing.T) {
	e := sigSetup(t, Config{})
	e.publish(t, "x", "1.0.0")
	cases := []struct {
		name  string
		ctype string
		body  string
		want  int
		msg   string
	}{
		{"not json", "application/json", "not json", 400, "does not verify"},
		{"empty", "application/json", "", 400, "does not verify"},
		{"array", "application/json", `[]`, 400, "does not verify"},
		{"wrong content type", "text/plain", sigBody, 400, "does not verify"},
		{"no content type", "", sigBody, 400, "does not verify"},
		{"no mediaType", "application/json", `{"verificationMaterial":{},"messageSignature":{}}`, 400, "mediaType"},
		{"mediaType not a string", "application/json", `{"mediaType":1,"verificationMaterial":{},"messageSignature":{}}`, 400, "mediaType"},
		{"wrong mediaType", "application/json", `{"mediaType":"application/json","verificationMaterial":{},"messageSignature":{}}`, 400, "mediaType"},
		{"no verificationMaterial", "application/json", `{"mediaType":"application/vnd.dev.sigstore.bundle+json","messageSignature":{}}`, 400, "verificationMaterial"},
		{"verificationMaterial not object", "application/json", `{"mediaType":"application/vnd.dev.sigstore.bundle+json","verificationMaterial":"x","messageSignature":{}}`, 400, "verificationMaterial"},
		{"no messageSignature", "application/json", `{"mediaType":"application/vnd.dev.sigstore.bundle+json","verificationMaterial":{}}`, 400, "messageSignature"},
		{"messageSignature null", "application/json", `{"mediaType":"application/vnd.dev.sigstore.bundle+json","verificationMaterial":{},"messageSignature":null}`, 400, "messageSignature"},
	}
	for _, tc := range cases {
		c, _, b := e.req(t, "PUT", sigPath, tc.ctype, []byte(tc.body))
		if c != tc.want || !strings.Contains(string(b), tc.msg) {
			t.Errorf("%s: %d %s", tc.name, c, b)
		}
	}
	// None of that stored anything, and a charset parameter is fine.
	if c, _, _ := e.req(t, "GET", sigPath, "", nil); c != 404 {
		t.Fatalf("a refused upload stored something: %d", c)
	}
	if c, _, b := e.req(t, "PUT", sigPath, "application/json; charset=utf-8", []byte(sigBody)); c != 201 {
		t.Fatalf("charset param: %d %s", c, b)
	}
}

func TestSignatureMessageStatesTheRegistryDoesNotVerify(t *testing.T) {
	e := sigSetup(t, Config{})
	e.publish(t, "x", "1.0.0")
	_, b := e.put(t, sigPath, `{}`)
	if !strings.Contains(string(b), "does not verify signatures") || !strings.Contains(string(b), "only checks the shape") {
		t.Fatalf("%s", b)
	}
}

func TestSignatureSizeLimit(t *testing.T) {
	e := sigSetup(t, Config{})
	e.publish(t, "x", "1.0.0")
	pad := func(n int) string {
		head := `{"mediaType":"application/vnd.dev.sigstore.bundle+json","verificationMaterial":{},"messageSignature":{},"pad":"`
		tail := `"}`
		return head + strings.Repeat("a", n-len(head)-len(tail)) + tail
	}
	if c, _ := e.put(t, sigPath, pad(65537)); c != 413 {
		t.Fatalf("65537 bytes: %d", c)
	}
	if c, b := e.put(t, sigPath, pad(65536)); c != 201 {
		t.Fatalf("65536 bytes: %d %s", c, b)
	}
}

func TestSignatureUnknownTargets404(t *testing.T) {
	e := sigSetup(t, Config{})
	e.publish(t, "x", "1.0.0")
	for _, p := range []string{
		"/v1/bundles/alice/x/9.9.9/signature",
		"/v1/bundles/alice/nope/1.0.0/signature",
	} {
		if c, b := e.put(t, p, sigBody); c != 404 {
			t.Errorf("PUT %s: %d %s", p, c, b)
		}
		if c, _, _ := e.req(t, "GET", p, "", nil); c != 404 {
			t.Errorf("GET %s: %d", p, c)
		}
	}
}

func TestSignaturePUTOnlyUnderOwnNamespace(t *testing.T) {
	e := sigSetup(t, Config{})
	e.publish(t, "x", "1.0.0")
	e.user.id, e.user.login = 2, "bob"
	if c, _ := e.put(t, sigPath, sigBody); c != 403 {
		t.Fatalf("stranger: %d", c)
	}
	e.user.id, e.user.login = 1, "alice"
	if c, _ := e.put(t, sigPath, sigBody); c != 201 {
		t.Fatalf("owner: %d", c)
	}
}

func TestSignatureOrgMemberMayUpload(t *testing.T) {
	e := sigSetup(t, Config{})
	e.st.UpsertUser(1, "alice")
	if err := e.st.ReplaceOrgMemberships(1, []store.OrgRecord{{OrgID: 77, Login: "acme", Role: store.RoleAdmin}}); err != nil {
		t.Fatal(err)
	}
	if c, b := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.0", bundle(t, "x", "1.0.0")); c != 201 {
		t.Fatalf("%d %s", c, b)
	}
	if c, b := e.put(t, "/v1/bundles/acme/x/1.0.0/signature", sigBody); c != 201 {
		t.Fatalf("member: %d %s", c, b)
	}
	// A non-member is refused.
	e.user.id, e.user.login = 2, "bob"
	if c, _ := e.put(t, "/v1/bundles/acme/x/1.0.0/signature", sigBody); c != 403 {
		t.Fatalf("non-member: %d", c)
	}
}

func TestSignatureSignedFlagInVersionsMetadataAndList(t *testing.T) {
	e := sigSetup(t, Config{})
	e.publish(t, "x", "1.0.0", "1.1.0")
	e.publish(t, "y", "1.0.0")
	e.put(t, "/v1/bundles/alice/x/1.1.0/signature", sigBody)

	_, b := e.do(t, "GET", "/v1/bundles/alice/x", nil)
	var vs []map[string]any
	if err := json.Unmarshal(b, &vs); err != nil || len(vs) != 2 || vs[0]["signed"] != false || vs[1]["signed"] != true {
		t.Fatalf("versions: %s", b)
	}
	for v, want := range map[string]bool{"1.0.0": false, "1.1.0": true} {
		_, b = e.do(t, "GET", "/v1/bundles/alice/x/"+v, nil)
		var m map[string]any
		if json.Unmarshal(b, &m) != nil || m["signed"] != want {
			t.Fatalf("metadata %s: %s", v, b)
		}
	}
	_, b = e.do(t, "GET", "/v1/bundles", nil)
	var list []map[string]any
	if err := json.Unmarshal(b, &list); err != nil || len(list) != 2 {
		t.Fatalf("list: %s", b)
	}
	got := map[string]any{}
	for _, it := range list {
		got[it["name"].(string)] = it["signed"]
	}
	if got["x"] != true || got["y"] != false {
		t.Fatalf("list signed: %v", got)
	}
	// A search result carries it too.
	_, b = e.do(t, "GET", "/v1/bundles?q=x", nil)
	if !strings.Contains(string(b), `"signed":true`) {
		t.Fatalf("search: %s", b)
	}
	// The list item reports the LATEST installable version: yank the signed
	// one and the bundle reads unsigned again; the signature itself stays.
	if c, _ := e.do(t, "POST", "/v1/bundles/alice/x/1.1.0/yank", nil); c != 200 {
		t.Fatal("yank")
	}
	_, b = e.do(t, "GET", "/v1/bundles?owner=alice&q=x", nil)
	list = nil
	json.Unmarshal(b, &list)
	if len(list) != 1 || list[0]["latest"] != "1.0.0" || list[0]["signed"] != false {
		t.Fatalf("after yank: %s", b)
	}
	if c, _, _ := e.req(t, "GET", "/v1/bundles/alice/x/1.1.0/signature", "", nil); c != 200 {
		t.Fatalf("yanked version's signature: %d", c)
	}
	_, b = e.do(t, "GET", "/v1/bundles/alice/x", nil)
	vs = nil
	json.Unmarshal(b, &vs)
	if vs[1]["signed"] != true {
		t.Fatalf("yank cleared signed: %s", b)
	}
}

func TestSignatureRemovedAndBannedServeNothing(t *testing.T) {
	e := sigSetup(t, Config{})
	e.publish(t, "x", "1.0.0", "1.1.0")
	e.put(t, "/v1/bundles/alice/x/1.0.0/signature", sigBody)
	e.put(t, "/v1/bundles/alice/x/1.1.0/signature", sigBody)

	e.user.id, e.user.login = adminID, "root"
	if c, b := e.do(t, "POST", "/v1/admin/bundles/alice/x/1.0.0/remove", reason("bad")); c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	e.user.ok = false
	if c, _, _ := e.req(t, "GET", "/v1/bundles/alice/x/1.0.0/signature", "", nil); c != 404 {
		t.Fatalf("removed: %d", c)
	}
	_, b := e.do(t, "GET", "/v1/bundles/alice/x", nil)
	var vs []map[string]any
	json.Unmarshal(b, &vs)
	if len(vs) != 2 || vs[0]["removed"] != true || vs[0]["signed"] != false || vs[1]["signed"] != true {
		t.Fatalf("%s", b)
	}
	// Banned owner: everything about the bundle 404s.
	e.user.ok, e.user.id, e.user.login = true, adminID, "root"
	if c, b := e.do(t, "POST", "/v1/admin/users/1/ban", reason("spam")); c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	e.user.ok = false
	if c, _, _ := e.req(t, "GET", "/v1/bundles/alice/x/1.1.0/signature", "", nil); c != 404 {
		t.Fatalf("banned: %d", c)
	}
}

func TestConcurrentSignaturePUTsOneWins(t *testing.T) {
	e := sigSetup(t, Config{PublishPerHour: 1000})
	e.publish(t, "x", "1.0.0")
	const n = 12
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := strings.Replace(sigBody, `"x":[1, 2]`, fmt.Sprintf(`"x":[%d]`, i), 1)
			codes[i], _, _ = e.req2(sigPath, "application/json", []byte(body))
		}()
	}
	wg.Wait()
	c201, c409 := 0, 0
	for _, c := range codes {
		switch c {
		case 201:
			c201++
		case 409:
			c409++
		default:
			t.Fatalf("codes: %v", codes)
		}
	}
	if c201 != 1 || c409 != n-1 {
		t.Fatalf("codes: %v", codes)
	}
}

// req2 is req without *testing.T, for goroutines.
func (e *sigEnv) req2(path, ctype string, body []byte) (int, http.Header, []byte) {
	req, _ := http.NewRequest("PUT", e.srv.URL+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", ctype)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, b
}

// Signature uploads have their own per-user hourly allowance, the same size as
// the publish one: they neither consume publish slots nor are unlimited.
func TestSignatureUploadsHaveTheirOwnRateLimit(t *testing.T) {
	e := sigSetup(t, Config{PublishPerHour: 2})
	e.publish(t, "x", "1.0.0", "1.1.0") // uses both publish slots
	if c, _ := e.do(t, "PUT", "/v1/bundles/alice/x/1.2.0", bundle(t, "x", "1.2.0")); c != 429 {
		t.Fatalf("publish allowance should be spent, got %d", c)
	}
	// The signatures still go through: separate allowance.
	for _, v := range []string{"1.0.0", "1.1.0"} {
		if c, b := e.put(t, "/v1/bundles/alice/x/"+v+"/signature", sigBody); c != 201 {
			t.Fatalf("%s: %d %s", v, c, b)
		}
	}
	// A third upload is over the signature allowance, even though it would
	// otherwise be a 409/404.
	c, h, _ := e.req(t, "PUT", "/v1/bundles/alice/x/1.0.0/signature", "application/json", []byte(sigBody))
	if c != 429 || h.Get("Retry-After") == "" {
		t.Fatalf("third upload: %d", c)
	}
	// The limit is per user.
	e.user.id, e.user.login = 2, "bob"
	if c, _ := e.put(t, "/v1/bundles/alice/x/1.0.0/signature", sigBody); c != 403 {
		t.Fatalf("other user: %d", c)
	}
}

func TestSignatureLimiterDoesNotSpendPublishSlots(t *testing.T) {
	e := sigSetup(t, Config{PublishPerHour: 2})
	e.publish(t, "x", "1.0.0")
	e.put(t, sigPath, sigBody)
	if c, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.1.0", bundle(t, "x", "1.1.0")); c != 201 {
		t.Fatalf("a signature upload consumed a publish slot: %d %s", c, b)
	}
}
