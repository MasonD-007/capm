package auth_test

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestUsageOfAnOrgIsVisibleToItsMembersOnly(t *testing.T) {
	e := setupOrgs(t)
	e.fixture()
	alice, _ := e.login(t, "alice", true)
	bob, _ := e.login(t, "bob", true)
	if code, b := e.do(t, "PUT", "/v1/bundles/acme/x/1.0.0", alice, bundle(t, "x", "1.0.0")); code != 201 {
		t.Fatalf("%d %s", code, b)
	}
	code, b := e.do(t, "GET", "/v1/auth/usage?owner=acme", alice, nil)
	var u struct{ Bundles, MaxBundles int64 }
	if code != 200 || json.Unmarshal(b, &u) != nil || u.Bundles != 1 {
		t.Fatalf("member: %d %s", code, b)
	}
	if code, b := e.do(t, "GET", "/v1/auth/usage?owner=alice", alice, nil); code != 200 || !strings.Contains(string(b), `"bundles":0`) {
		t.Fatalf("own login: %d %s", code, b)
	}
	if code, b := e.do(t, "GET", "/v1/auth/usage", alice, nil); code != 200 || !strings.Contains(string(b), `"bundles":0`) {
		t.Fatalf("default: %d %s", code, b)
	}
	for _, owner := range []string{"acme", "alice", "nobody"} {
		if code, _ := e.do(t, "GET", "/v1/auth/usage?owner="+owner, bob, nil); code != 403 {
			t.Errorf("bob sees %s's usage: %d", owner, code)
		}
	}
	e.age(t, 25*time.Hour)
	if code, _ := e.do(t, "GET", "/v1/auth/usage?owner=acme", alice, nil); code != 403 {
		t.Fatalf("stale: %d", code)
	}
}
