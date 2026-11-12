package auth_test

import (
	"encoding/json"
	"testing"
)

func TestUsageRequiresAuthAndReportsCallerOnly(t *testing.T) {
	e := setup(t, "cid")
	if code, _ := e.do(t, "GET", "/v1/auth/usage", "", nil); code != 401 {
		t.Fatalf("no token: %d", code)
	}
	if code, _ := e.do(t, "GET", "/v1/auth/usage", "garbage", nil); code != 401 {
		t.Fatalf("garbage token: %d", code)
	}
	tok := e.login(t)
	get := func() map[string]any {
		code, b := e.do(t, "GET", "/v1/auth/usage", tok, nil)
		if code != 200 {
			t.Fatalf("%d %s", code, b)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	m := get()
	want := map[string]float64{"bytes": 0, "maxBytes": 100 << 20, "bundles": 0, "maxBundles": 50, "maxBundleVersions": 200}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %v, want %v (body %v)", k, m[k], v, m)
		}
	}
	if len(m) != len(want) {
		t.Errorf("unexpected fields: %v", m)
	}

	tb := bundle(t, "x", "1.0.0")
	if code, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", tok, tb); code != 201 {
		t.Fatalf("%d %s", code, b)
	}
	m = get()
	if m["bytes"] != float64(len(tb)) || m["bundles"] != float64(1) {
		t.Fatalf("after publish: %v", m)
	}
	// An override shows up as the caller's limit.
	if err := e.st.SetQuotaOverride(99, 42, ptr(int64(777)), nil); err != nil {
		t.Fatal(err)
	}
	if m = get(); m["maxBytes"] != float64(777) {
		t.Fatalf("override not reported: %v", m)
	}
}

func ptr[T any](v T) *T { return &v }
