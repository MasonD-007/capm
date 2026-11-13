package main

import (
	"strings"
	"testing"
)

// An organisation's bundle is pinned to the organisation's account id, exactly
// like a user's: no pin code changed, the id in the registry's reply is the
// owner's whatever its kind.
func TestOrgBundlePinsTheOrgsID(t *testing.T) {
	h := pinHarness(t, "", false)
	h.reg.add("acme", "pr-reviewer", "0.1.0", fixtureTar(t, "0.1.0", nil), false)
	h.reg.ownerID = 77
	target := "acme/pr-reviewer@0.1.0"
	if code := h.runArgs("--yes", "--allow-unenforced-egress", target); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	r, ok := newKnownStore(h.env, &strings.Builder{}).get(h.env.registry, "acme", "pr-reviewer")
	if !ok || r.OwnerID != 77 {
		t.Fatalf("record %+v ok=%v", r, ok)
	}
	// The org's name is taken over by another account: refused.
	h.reg.ownerID = 78
	if code := h.runArgs("--yes", "--allow-unenforced-egress", target); code != 1 || !strings.Contains(h.errb.String(), "--accept-new-owner") {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
}
