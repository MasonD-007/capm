package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MasonD-007/capm/cli/internal/sigverify"
)

const wantInspectValid = "signature: valid for the digest the registry reports (a GitHub Actions workflow in alice/pr-reviewer-src: " +
	"https://github.com/alice/pr-reviewer-src/.github/workflows/publish.yml@refs/tags/v0.1.0, commit 0123456); " +
	"the bundle itself was not downloaded, so capm did not check it against this signature"

func (s *sigT) inspect(extra ...string) int {
	return s.run(append([]string{"inspect", refTarget}, extra...)...)
}

// registrySaysSigned makes the fake registry's metadata report signed: true.
func (s *sigT) registrySaysSigned() { s.reg.metaExtra = map[string]any{"signed": true} }

func TestInspectSignedValidWording(t *testing.T) {
	s := newSigT(t, "", false)
	s.signed()
	s.registrySaysSigned()
	if code := s.inspect(); code != 0 {
		t.Fatalf("exit %d: %s", code, s.stderr())
	}
	e := s.stderr()
	if !strings.Contains(e, wantInspectValid+"\n") {
		t.Errorf("stderr:\n%s", e)
	}
	// It must not say the bundle is verified.
	if strings.Contains(e, "signature: verified") {
		t.Error("inspect says verified for a bundle it did not download")
	}
	if s.reg.downloads != 0 {
		t.Error("inspect downloaded the bundle")
	}
	// The digest handed to the verifier is the one the registry reports.
	want := sha256Of(s.reg.versions["alice/pr-reviewer@0.1.0"].tar)
	if len(s.vf.calls) != 1 || !bytes.Equal(s.vf.calls[0].digest, want) {
		t.Fatalf("verifier calls %d; want digest %s", len(s.vf.calls), hex.EncodeToString(want))
	}
	if s.vf.calls[0].want.OwnerID != 0 || s.vf.calls[0].want.RepositoryID != 0 {
		t.Errorf("inspect passed pins to the verifier: %+v", s.vf.calls[0].want)
	}
	if s.out.Len() == 0 {
		t.Error("the summary is gone")
	}
	if s.knownFileExists() {
		t.Error("inspect wrote known.json")
	}
}

func TestInspectUnsignedClaimMakesNoSignatureRequest(t *testing.T) {
	for _, extra := range []map[string]any{nil, {"signed": false}} {
		s := newSigT(t, "", false)
		s.signed() // a signature exists, but the registry did not say so
		s.reg.metaExtra = extra
		if code := s.inspect(); code != 0 {
			t.Fatalf("exit %d: %s", code, s.stderr())
		}
		if !strings.Contains(s.stderr(), "signature: none reported by the registry (capm has checked nothing") {
			t.Errorf("stderr:\n%s", s.stderr())
		}
		if sig, _ := s.proxy.counts(); sig != 0 || s.vf.callCount() != 0 {
			t.Errorf("unsigned claim triggered a signature request (%d) or a verification", sig)
		}
		assertNoVerifiedClaim(t, s.stderr())
	}
}

func TestInspectSignedFailuresExit1(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*sigT)
		want  string
	}{
		{"untrusted", func(s *sigT) { s.vf.err = &sigverify.Error{Kind: sigverify.ErrUntrusted} }, "the signature attached to alice/pr-reviewer@0.1.0 did not verify: it does not match this download"},
		{"malformed", func(s *sigT) { s.vf.err = &sigverify.Error{Kind: sigverify.ErrMalformed} }, "did not verify: it is malformed"},
		{"identity", func(s *sigT) { s.vf.err = &sigverify.IdentityError{Field: "owner login", Reason: "mismatch"} }, "did not verify: it was made for a different owner or repository"},
		{"stale", func(s *sigT) {
			s.vf.err = &sigverify.StaleTrustRootError{Reason: "x"}
			s.env.upd.exePath = func() (string, error) { return "/opt/homebrew/Cellar/capm/1/bin/capm", nil }
		}, "this version of capm cannot check this signature because its built-in trust material is out of date or does not cover the signer. To fix this, run brew upgrade capm and try again"},
		{"claimed but absent", func(s *sigT) { s.proxy.set("alice", "pr-reviewer", "0.1.0", 404, nil) }, "the registry says alice/pr-reviewer@0.1.0 is signed but serves no signature for it"},
		{"fetch error", func(s *sigT) { s.proxy.set("alice", "pr-reviewer", "0.1.0", 500, nil) }, "its signature could not be fetched"},
		{"owner disagreement", func(s *sigT) { s.vf.id.OwnerID = 9; s.vf.honour = false }, "the registry and the signature disagree about who owns alice/pr-reviewer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSigT(t, "", false)
			s.signed()
			s.registrySaysSigned()
			tc.setup(s)
			code := s.inspect()
			e := s.stderr()
			if code != 1 || !strings.Contains(e, tc.want) {
				t.Fatalf("exit %d:\n%s", code, e)
			}
			if strings.Contains(e, "signature: valid") || strings.Contains(e, "signature: verified") {
				t.Error("success wording on a failure")
			}
			assertNoVerifiedClaim(t, e)
			if s.knownFileExists() {
				t.Error("inspect wrote known.json")
			}
		})
	}
}

func TestInspectShowsPinnedSignerAndNeverWrites(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed func(*knownRecord)
		want string
	}{
		{"unpinned", nil, "signer pin: not pinned yet"},
		{"match", func(r *knownRecord) {
			r.OwnerID = 7
			r.SignerPin = &signerPin{OwnerID: 7, RepositoryID: 555, Repository: "alice/pr-reviewer-src", VerifiedVersion: "0.0.1"}
		}, "signer pin: signed from the repository you pinned (alice/pr-reviewer-src)"},
		{"repository differs", func(r *knownRecord) {
			r.OwnerID = 7
			r.SignerPin = &signerPin{OwnerID: 7, RepositoryID: 111, Repository: "alice/first-repo", VerifiedVersion: "0.0.1"}
		}, "signer pin: WARNING signed from alice/pr-reviewer-src (id 555) but you pinned alice/first-repo (id 111); run/pull will refuse without --accept-new-signer"},
		{"owner differs", func(r *knownRecord) { r.OwnerID = 5 }, "signer pin: WARNING signed by owner id 7 but you pinned 5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSigT(t, "", false)
			s.signed()
			s.registrySaysSigned()
			if tc.seed != nil {
				s.seed(t, tc.seed)
			}
			path := filepath.Join(s.env.credDir, knownFileName)
			before, _ := os.ReadFile(path)
			if code := s.inspect(); code != 0 {
				t.Fatalf("exit %d: %s", code, s.stderr())
			}
			if !strings.Contains(s.stderr(), tc.want) {
				t.Errorf("stderr:\n%s", s.stderr())
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Error("inspect modified known.json")
			}
			// Pins are compared by inspect itself, never handed to the verifier.
			if c := s.vf.calls[0].want; c.OwnerID != 0 || c.RepositoryID != 0 {
				t.Errorf("pins passed to verifier: %+v", c)
			}
		})
	}
}

func TestInspectUnsignedShowsEarlierSignedPin(t *testing.T) {
	s := newSigT(t, "", false)
	s.seed(t, func(r *knownRecord) {
		r.OwnerID = 7
		r.SignerPin = &signerPin{OwnerID: 7, RepositoryID: 555, Repository: "alice/pr-reviewer-src", VerifiedVersion: "0.0.1"}
	})
	if code := s.inspect(); code != 0 {
		t.Fatalf("exit %d: %s", code, s.stderr())
	}
	if !strings.Contains(s.stderr(), "signer pin: you pinned alice/pr-reviewer-src (repository id 555) when you used version 0.0.1, which was signed; this version is not") {
		t.Errorf("stderr:\n%s", s.stderr())
	}
}

func TestInspectDiffStillWorksWithSignatures(t *testing.T) {
	s := newSigT(t, "", false)
	s.signed()
	s.registrySaysSigned()
	if code := s.inspect("--diff"); code != 0 {
		t.Fatalf("exit %d: %s", code, s.stderr())
	}
	if !strings.Contains(s.stderr(), "signature: valid for the digest the registry reports") {
		t.Errorf("stderr:\n%s", s.stderr())
	}
}
