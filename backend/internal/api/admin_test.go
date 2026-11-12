package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MasonD-007/capm/backend/internal/store"
)

const adminID = 99

// adminEnv is an env whose caller can be switched between alice (1), bob (2),
// the admin (99) and nobody.
func adminEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	e := &env{dir: dir}
	e.user = &struct {
		id    int64
		login string
		ok    bool
	}{1, "alice", true}
	a := NewWithConfig(s, func(r *http.Request) (int64, string, bool) { return e.user.id, e.user.login, e.user.ok },
		Config{IsAdmin: func(id int64) bool { return id == adminID }})
	e.srv = httptest.NewServer(a.Handler())
	t.Cleanup(e.srv.Close)
	return e
}

func sha(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func (e *env) asAdmin()      { e.user.id, e.user.login, e.user.ok = adminID, "root", true }
func (e *env) asAlice()      { e.user.id, e.user.login, e.user.ok = 1, "alice", true }
func (e *env) asNobody()     { e.user.ok = false }
func reason(r string) []byte { b, _ := json.Marshal(map[string]string{"reason": r}); return b }

func (e *env) code(t *testing.T, method, path string, body []byte) int {
	t.Helper()
	c, _ := e.do(t, method, path, body)
	return c
}

func TestAdminRoutes404ForEveryoneButAdmins(t *testing.T) {
	e := adminEnv(t)
	publishVersions(t, e, "1.0.0")
	routes := [][2]string{
		{"POST", "/v1/admin/bundles/alice/x/1.0.0/remove"},
		{"DELETE", "/v1/admin/bundles/alice/x/1.0.0/remove"},
		{"POST", "/v1/admin/bundles/alice/x/remove"},
		{"DELETE", "/v1/admin/bundles/alice/x/remove"},
		{"POST", "/v1/admin/users/1/ban"},
		{"DELETE", "/v1/admin/users/1/ban"},
		{"GET", "/v1/admin/log"},
		{"GET", "/v1/admin/"},
		{"GET", "/v1/admin/whatever/else"},
		{"PATCH", "/v1/admin/log"},
	}
	_, unknown := e.do(t, "GET", "/v1/nonexistent", nil)
	for _, who := range []string{"alice", "nobody"} {
		if who == "alice" {
			e.asAlice()
		} else {
			e.asNobody()
		}
		for _, r := range routes {
			c, b := e.do(t, r[0], r[1], reason("x"))
			if c != 404 {
				t.Errorf("%s %s %s: %d, want 404", who, r[0], r[1], c)
			}
			if !bytes.Equal(b, unknown) {
				t.Errorf("%s %s %s: body %q differs from an unknown route %q", who, r[0], r[1], b, unknown)
			}
		}
	}
	// Nothing happened.
	e.asAdmin()
	_, b := e.do(t, "GET", "/v1/admin/log", nil)
	if strings.TrimSpace(string(b)) != "[]" {
		t.Fatalf("audit log should be empty: %s", b)
	}
}

type versionItem struct {
	Version       string `json:"version"`
	Digest        string `json:"digest"`
	Yanked        bool   `json:"yanked"`
	Removed       bool   `json:"removed"`
	RemovedReason string `json:"removedReason"`
}

func (e *env) versionItems(t *testing.T) []versionItem {
	t.Helper()
	c, b := e.do(t, "GET", "/v1/bundles/alice/x", nil)
	if c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	var out []versionItem
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

type goneBody struct {
	Error   string `json:"error"`
	Reason  string `json:"reason"`
	Removed bool   `json:"removed"`
}

func TestRemovedVersionReturns410Everywhere(t *testing.T) {
	e := adminEnv(t)
	publishVersions(t, e, "1.0.0", "1.1.0")
	e.asAdmin()
	c, b := e.do(t, "POST", "/v1/admin/bundles/alice/x/1.1.0/remove", reason("contains malware"))
	if c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	e.asNobody()
	for _, p := range []string{
		"/v1/bundles/alice/x/1.1.0/download",
		"/v1/bundles/alice/x/1.1.0",
		"/v1/bundles/alice/x/resolve?range=1.1.0",
	} {
		c, b := e.do(t, "GET", p, nil)
		var g goneBody
		json.Unmarshal(b, &g)
		if c != 410 || g.Reason != "contains malware" || !g.Removed || !strings.Contains(g.Error, "contains malware") {
			t.Errorf("%s: %d %s", p, c, b)
		}
	}
	// latest skips it, even though it is the highest.
	if c, r := e.resolve(t, "latest"); c != 200 || r.Version != "1.0.0" {
		t.Fatalf("%d %+v", c, r)
	}
	if l := e.list(t); len(l) != 1 || l[0].Latest != "1.0.0" {
		t.Fatalf("%+v", l)
	}
	// Still listed, flagged. Old fields are all still present.
	vs := e.versionItems(t)
	if len(vs) != 2 || !vs[1].Removed || vs[1].RemovedReason != "contains malware" || vs[0].Removed {
		t.Fatalf("%+v", vs)
	}
	_, raw := e.do(t, "GET", "/v1/bundles/alice/x", nil)
	for _, f := range []string{`"version"`, `"digest"`, `"yanked"`, `"manifest"`, `"summary"`, `"createdAt"`, `"removed"`, `"removedReason"`} {
		if !bytes.Contains(raw, []byte(f)) {
			t.Errorf("versions list lacks %s", f)
		}
	}
	// The number can never be republished.
	e.asAlice()
	if c := e.code(t, "PUT", "/v1/bundles/alice/x/1.1.0", bundle(t, "x", "1.1.0")); c != 409 {
		t.Fatalf("republish: %d", c)
	}
	// A live version still downloads.
	if c := e.code(t, "GET", "/v1/bundles/alice/x/1.0.0/download", nil); c != 200 {
		t.Fatalf("live download %d", c)
	}
}

func TestRemovedManifestNotServed(t *testing.T) {
	e := adminEnv(t)
	publishVersions(t, e, "1.0.0")
	e.asAdmin()
	e.do(t, "POST", "/v1/admin/bundles/alice/x/1.0.0/remove", reason("bad"))
	_, b := e.do(t, "GET", "/v1/bundles/alice/x", nil)
	if bytes.Contains(b, []byte("claude-code")) {
		t.Fatalf("a removed version's manifest must not be served: %s", b)
	}
}

func TestAllVersionsRemovedResolveLatest410(t *testing.T) {
	e := adminEnv(t)
	publishVersions(t, e, "1.0.0", "1.1.0")
	e.asAdmin()
	if c, b := e.do(t, "POST", "/v1/admin/bundles/alice/x/remove", reason("whole bundle bad")); c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	c, b := e.do(t, "GET", "/v1/bundles/alice/x/resolve", nil)
	var g goneBody
	json.Unmarshal(b, &g)
	if c != 410 || g.Reason != "whole bundle bad" {
		t.Fatalf("%d %s", c, b)
	}
	// Removed-only bundle stays in the list with no latest.
	if l := e.list(t); len(l) != 1 || l[0].Latest != "" {
		t.Fatalf("%+v", l)
	}
}

func TestAdminRemoveValidationAndConflicts(t *testing.T) {
	e := adminEnv(t)
	publishVersions(t, e, "1.0.0")
	e.asAdmin()
	p := "/v1/admin/bundles/alice/x/1.0.0/remove"
	for _, body := range [][]byte{nil, []byte("{}"), reason("   "), reason(strings.Repeat("a", 501)), []byte("nope")} {
		if c := e.code(t, "POST", p, body); c != 400 {
			t.Errorf("body %q: %d, want 400", body, c)
		}
	}
	if c := e.code(t, "POST", "/v1/admin/bundles/alice/x/9.9.9/remove", reason("r")); c != 404 {
		t.Errorf("unknown version %d", c)
	}
	if c := e.code(t, "POST", "/v1/admin/bundles/alice/nope/remove", reason("r")); c != 404 {
		t.Errorf("unknown bundle %d", c)
	}
	if c := e.code(t, "POST", "/v1/admin/bundles/~1/x/1.0.0/remove", reason("r")); c != 404 {
		t.Errorf("tombstone owner %d", c)
	}
	if c := e.code(t, "POST", p, reason("r")); c != 200 {
		t.Fatalf("%d", c)
	}
	if c := e.code(t, "POST", p, reason("r")); c != 409 {
		t.Errorf("second remove %d, want 409", c)
	}
}

func TestAdminAuditLog(t *testing.T) {
	e := adminEnv(t)
	publishVersions(t, e, "1.0.0")
	e.asAdmin()
	e.do(t, "POST", "/v1/admin/bundles/alice/x/1.0.0/remove", reason("because"))
	e.do(t, "POST", "/v1/admin/users/1/ban", reason("spam"))
	c, b := e.do(t, "GET", "/v1/admin/log?limit=10", nil)
	if c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	var log []struct {
		ID      int64  `json:"id"`
		AdminID int64  `json:"adminId"`
		Action  string `json:"action"`
		Target  string `json:"target"`
		Reason  string `json:"reason"`
		At      string `json:"createdAt"`
	}
	if err := json.Unmarshal(b, &log); err != nil || len(log) != 2 {
		t.Fatalf("%v %s", err, b)
	}
	if log[0].Action != "ban_user" || log[0].Target != "user:1" || log[0].AdminID != adminID || log[0].At == "" {
		t.Fatalf("%+v", log[0])
	}
	if log[1].Action != "remove_version" || log[1].Target != "alice/x@1.0.0" || log[1].Reason != "because" {
		t.Fatalf("%+v", log[1])
	}
	if c := e.code(t, "GET", "/v1/admin/log?limit=0", nil); c != 400 {
		t.Errorf("limit=0: %d", c)
	}
}

func TestAdminRestoreAfterBlobDeletedIs409(t *testing.T) {
	e := adminEnv(t)
	publishVersions(t, e, "1.0.0")
	e.asAdmin()
	e.do(t, "POST", "/v1/admin/bundles/alice/x/1.0.0/remove", reason("r"))
	c, b := e.do(t, "DELETE", "/v1/admin/bundles/alice/x/1.0.0/remove", nil)
	if c != 409 || !strings.Contains(string(b), "deleted") {
		t.Fatalf("%d %s", c, b)
	}
	if v := e.versionItems(t); !v[0].Removed {
		t.Fatal("must stay removed")
	}
}

func TestAdminRestoreWhenBlobPresent(t *testing.T) {
	e := adminEnv(t)
	tbs := publishVersions(t, e, "1.0.0", "1.1.0")
	// Keep a copy of the blob to put back, as restoring from a backup would.
	var blob string
	filepath.Walk(filepath.Join(e.dir, "blobs"), func(p string, i os.FileInfo, err error) error {
		if err == nil && !i.IsDir() {
			if d, _ := os.ReadFile(p); bytes.Equal(d, tbs["1.1.0"]) {
				blob = p
			}
		}
		return nil
	})
	if blob == "" {
		t.Fatal("blob not found")
	}
	e.asAdmin()
	e.do(t, "POST", "/v1/admin/bundles/alice/x/1.1.0/remove", reason("r"))
	if _, err := os.Stat(blob); err == nil {
		t.Fatal("blob should have been deleted")
	}
	os.WriteFile(blob, tbs["1.1.0"], 0o644)
	if c, b := e.do(t, "DELETE", "/v1/admin/bundles/alice/x/1.1.0/remove", nil); c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	e.asNobody()
	if c := e.code(t, "GET", "/v1/bundles/alice/x/1.1.0/download", nil); c != 200 {
		t.Fatalf("download after restore %d", c)
	}
	if c, r := e.resolve(t, "latest"); c != 200 || r.Version != "1.1.0" {
		t.Fatalf("%d %+v", c, r)
	}
	e.asAdmin()
	if c := e.code(t, "DELETE", "/v1/admin/bundles/alice/x/1.1.0/remove", nil); c != 409 {
		t.Fatalf("restoring a live version: %d", c)
	}
}

func TestAdminBundleRestoreReportsSkipped(t *testing.T) {
	e := adminEnv(t)
	tbs := publishVersions(t, e, "1.0.0", "1.1.0")
	e.asAdmin()
	e.do(t, "POST", "/v1/admin/bundles/alice/x/remove", reason("r"))
	// Restore only 1.0.0's blob.
	h := sha(tbs["1.0.0"])
	os.WriteFile(filepath.Join(e.dir, "blobs", h), tbs["1.0.0"], 0o644)
	c, b := e.do(t, "DELETE", "/v1/admin/bundles/alice/x/remove", nil)
	var out struct {
		Restored []string `json:"restored"`
		Skipped  []string `json:"skipped"`
	}
	json.Unmarshal(b, &out)
	if c != 200 || len(out.Restored) != 1 || out.Restored[0] != "1.0.0" || len(out.Skipped) != 1 {
		t.Fatalf("%d %s", c, b)
	}
}

func TestAdminBan(t *testing.T) {
	e := adminEnv(t)
	publishVersions(t, e, "1.0.0")
	e.asAdmin()
	// By login.
	if c, b := e.do(t, "POST", "/v1/admin/users/alice/ban", reason("spam")); c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	e.asNobody()
	// Bundles of a banned owner: hidden from list, 404 on every direct route.
	if l := e.list(t); len(l) != 0 {
		t.Fatalf("list leaks banned owner: %+v", l)
	}
	for _, p := range []string{
		"/v1/bundles/alice/x",
		"/v1/bundles/alice/x/1.0.0",
		"/v1/bundles/alice/x/1.0.0/download",
		"/v1/bundles/alice/x/resolve",
		"/v1/bundles?owner=alice&q=x",
	} {
		c, b := e.do(t, "GET", p, nil)
		if strings.HasPrefix(p, "/v1/bundles?") {
			if c != 200 || strings.TrimSpace(string(b)) != "[]" {
				t.Errorf("%s: %d %s", p, c, b)
			}
			continue
		}
		if c != 404 {
			t.Errorf("%s: %d, want 404", p, c)
		}
	}
	e.asAdmin()
	if c := e.code(t, "POST", "/v1/admin/users/alice/ban", reason("again")); c != 409 {
		t.Errorf("double ban %d", c)
	}
	if c, b := e.do(t, "DELETE", "/v1/admin/users/alice/ban", nil); c != 200 {
		t.Fatalf("unban %d %s", c, b)
	}
	if c := e.code(t, "DELETE", "/v1/admin/users/alice/ban", nil); c != 404 {
		t.Errorf("unban twice %d", c)
	}
	e.asNobody()
	if l := e.list(t); len(l) != 1 {
		t.Fatalf("unban must restore: %+v", l)
	}
	// Validation, unknown login, numeric ids, admins cannot be banned.
	e.asAdmin()
	if c := e.code(t, "POST", "/v1/admin/users/alice/ban", nil); c != 400 {
		t.Errorf("no reason %d", c)
	}
	if c := e.code(t, "POST", "/v1/admin/users/nobody-here/ban", reason("r")); c != 404 {
		t.Errorf("unknown login %d", c)
	}
	if c := e.code(t, "POST", "/v1/admin/users/12345/ban", reason("pre-emptive")); c != 200 {
		t.Errorf("numeric id of unseen user %d", c)
	}
	if c := e.code(t, "POST", "/v1/admin/users/99/ban", reason("oops")); c != 400 {
		t.Errorf("banning an admin %d", c)
	}
}
