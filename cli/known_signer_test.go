package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestKnownFileFromBeforeSignaturesLoadsAndUpgrades(t *testing.T) {
	ks, _, path := testKnown(t)
	os.MkdirAll(filepath.Dir(path), 0o700)
	old := `{"version":1,"registries":{"r":{"alice/x":{"ownerId":5,"pinnedAt":"2026-11-01T00:00:00Z","lastRun":{"version":"1.0.0","digest":"sha256:abc","at":"2026-11-01T00:00:00Z"}}}}}`
	os.WriteFile(path, []byte(old), 0o600)
	r, ok := ks.get("r", "alice", "x")
	if !ok || r.OwnerID != 5 || r.SignerPin != nil || r.LastRun == nil {
		t.Fatalf("old file: %+v ok=%v", r, ok)
	}
	err := ks.update("r", "alice", "x", func(r *knownRecord) {
		r.SignerPin = &signerPin{OwnerID: 5, RepositoryID: 9, Repository: "alice/x-src", VerifiedVersion: "1.0.1", At: time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)}
	})
	if err != nil {
		t.Fatal(err)
	}
	ks2 := newKnownStore(env{credDir: filepath.Dir(path)}, &bytes.Buffer{})
	r2, _ := ks2.get("r", "alice", "x")
	if r2.OwnerID != 5 || r2.LastRun == nil || r2.SignerPin == nil || r2.SignerPin.RepositoryID != 9 || r2.SignerPin.Repository != "alice/x-src" || r2.SignerPin.VerifiedVersion != "1.0.1" {
		t.Fatalf("after upgrade: %+v / %+v", r2, r2.SignerPin)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), `"signerPin"`) {
		t.Errorf("file:\n%s", b)
	}
}

func TestKnownSignerUnknownFieldsRoundTrip(t *testing.T) {
	ks, _, path := testKnown(t)
	os.MkdirAll(filepath.Dir(path), 0o700)
	in := `{"version":1,"top":{"a":1},"registries":{"r":{"alice/x":{"ownerId":5,"recordFuture":[1,2],` +
		`"signerPin":{"ownerId":5,"repositoryId":9,"repository":"alice/x-src","verifiedVersion":"1.0.0","at":"2026-11-01T00:00:00Z","signerFuture":"keep-me"}}}}}`
	os.WriteFile(path, []byte(in), 0o600)
	if err := ks.update("r", "alice", "x", func(r *knownRecord) {
		r.SignerPin.VerifiedVersion = "1.0.1"
	}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	s := strings.Join(strings.Fields(string(b)), "")
	for _, want := range []string{`"top":{"a":1}`, `"recordFuture":[1,2]`, `"signerFuture":"keep-me"`, `"verifiedVersion":"1.0.1"`, `"repositoryId":9`} {
		if !strings.Contains(s, want) {
			t.Errorf("lost %s:\n%s", want, b)
		}
	}
}

// An existing (pre-signature) file may already use "signer" for something
// else; the new member is "signerPin" so that cannot be confused with it.
func TestKnownOlderSignerMemberStillPreserved(t *testing.T) {
	ks, _, path := testKnown(t)
	os.MkdirAll(filepath.Dir(path), 0o700)
	os.WriteFile(path, []byte(`{"version":1,"registries":{"r":{"alice/x":{"ownerId":5,"signer":"someone"}}}}`), 0o600)
	r, ok := ks.get("r", "alice", "x")
	if !ok || r.SignerPin != nil || r.OwnerID != 5 {
		t.Fatalf("%+v %v", r, ok)
	}
}
