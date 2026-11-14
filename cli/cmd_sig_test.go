package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/MasonD-007/capm/cli/internal/sigverify"
)

const (
	wantVerifiedLine = "signature: verified — signed by a GitHub Actions workflow in alice/pr-reviewer-src " +
		"(https://github.com/alice/pr-reviewer-src/.github/workflows/publish.yml@refs/tags/v0.1.0, commit 0123456)"
	wantUnsignedLine = "signature: none (this version is unsigned; its publisher is identified only by the registry)"
)

// --- unsigned ------------------------------------------------------------

func TestPullUnsignedProceedsAsBefore(t *testing.T) {
	s := newSigT(t, "", false)
	if code := s.pull(); code != 0 {
		t.Fatalf("exit %d: %s", code, s.stderr())
	}
	if !strings.Contains(s.stderr(), wantUnsignedLine+"\n") {
		t.Errorf("stderr lacks the unsigned line:\n%s", s.stderr())
	}
	if s.vf.callCount() != 0 {
		t.Error("the verifier ran without a signature")
	}
	if !s.pulledDirExists() {
		t.Error("nothing pulled")
	}
	r, ok := s.rec(t)
	if !ok || r.OwnerID != 7 || r.SignerPin != nil {
		t.Errorf("record %+v ok=%v (owner pin as before, no signer)", r, ok)
	}
	assertNoVerifiedClaim(t, s.stderr())
}

func TestRunUnsignedProceedsAsBefore(t *testing.T) {
	s := newSigT(t, "", false)
	if code := s.runBundle(); code != 0 {
		t.Fatalf("exit %d: %s", code, s.stderr())
	}
	if !strings.Contains(s.stderr(), wantUnsignedLine+"\n") {
		t.Errorf("stderr:\n%s", s.stderr())
	}
	if !s.runner.has("create") {
		t.Error("plan not executed")
	}
	if r, _ := s.rec(t); r.SignerPin != nil || r.LastRun == nil {
		t.Errorf("record %+v", r)
	}
	assertNoVerifiedClaim(t, s.stderr())
}

func TestUnsignedAfterEarlierSignedIsOnlyANote(t *testing.T) {
	for _, cmd := range []string{"pull", "run"} {
		t.Run(cmd, func(t *testing.T) {
			s := newSigT(t, "", false)
			s.seed(t, func(r *knownRecord) {
				r.OwnerID = 7
				r.SignerPin = &signerPin{OwnerID: 7, RepositoryID: 555, Repository: "alice/pr-reviewer-src", VerifiedVersion: "0.0.9", At: time.Now()}
			})
			var code int
			if cmd == "pull" {
				code = s.pull()
			} else {
				code = s.runBundle()
			}
			if code != 0 {
				t.Fatalf("exit %d (a later unsigned version must not be refused): %s", code, s.stderr())
			}
			e := s.stderr()
			if !strings.Contains(e, wantUnsignedLine) || !strings.Contains(e, "signature: note: version 0.0.9, which you used earlier, was signed from alice/pr-reviewer-src; this version is not signed") {
				t.Errorf("stderr:\n%s", e)
			}
			// The signer pin stays as it was.
			if r, _ := s.rec(t); r.SignerPin == nil || r.SignerPin.VerifiedVersion != "0.0.9" {
				t.Errorf("signer pin changed by an unsigned version: %+v", r.SignerPin)
			}
		})
	}
}

// --- verified ------------------------------------------------------------

func TestPullVerifiedFirstUsePinsFromCertificate(t *testing.T) {
	s := newSigT(t, "", false)
	s.signed()
	if code := s.pull(); code != 0 {
		t.Fatalf("exit %d: %s", code, s.stderr())
	}
	if !strings.Contains(s.stderr(), wantVerifiedLine+"\n") {
		t.Errorf("stderr lacks the verified line:\n%s", s.stderr())
	}
	if len(s.vf.calls) != 1 {
		t.Fatalf("verifier calls: %d", len(s.vf.calls))
	}
	c := s.vf.calls[0]
	if string(c.sig) != string(fakeSigBytes) {
		t.Error("verifier got different signature bytes")
	}
	if want := sha256Of(s.reg.versions["alice/pr-reviewer@0.1.0"].tar); !bytes.Equal(c.digest, want) {
		t.Errorf("verifier digest is not the sha256 of the downloaded tarball")
	}
	if c.want.OwnerLogin != "alice" || c.want.OwnerID != 0 || c.want.RepositoryID != 0 || c.want.Repository != "" {
		t.Errorf("first use must not invent pins: %+v", c.want)
	}
	r, _ := s.rec(t)
	p := r.SignerPin
	if r.OwnerID != 7 || p == nil || p.OwnerID != 7 || p.RepositoryID != 555 || p.Repository != "alice/pr-reviewer-src" || p.VerifiedVersion != "0.1.0" || p.At.IsZero() {
		t.Errorf("record %+v signer %+v", r, p)
	}
	if !s.pulledDirExists() {
		t.Error("nothing pulled")
	}
}

func TestVerifiedWithMatchingPins(t *testing.T) {
	s := newSigT(t, "", false)
	s.signed()
	s.seed(t, func(r *knownRecord) {
		r.OwnerID = 7
		r.SignerPin = &signerPin{OwnerID: 7, RepositoryID: 555, Repository: "alice/old-name", VerifiedVersion: "0.0.1"}
	})
	if code := s.runBundle(); code != 0 {
		t.Fatalf("exit %d: %s", code, s.stderr())
	}
	if !strings.Contains(s.stderr(), wantVerifiedLine) || !strings.Contains(s.stderr(), "signed from the repository you pinned") {
		t.Errorf("stderr:\n%s", s.stderr())
	}
	w := s.vf.calls[0].want
	if w.OwnerID != 7 || w.RepositoryID != 555 {
		t.Errorf("pinned ids not passed to the verifier: %+v", w)
	}
	// A renamed repository keeps its id; the name and version are refreshed.
	if r, _ := s.rec(t); r.SignerPin.Repository != "alice/pr-reviewer-src" || r.SignerPin.VerifiedVersion != "0.1.0" {
		t.Errorf("signer %+v", r.SignerPin)
	}
}

func TestManifestRepositoryIsPassedWhenItBelongsToTheOwner(t *testing.T) {
	for _, tc := range []struct{ repo, want string }{
		{"https://github.com/alice/pr-reviewer-src", "alice/pr-reviewer-src"},
		{"https://github.com/Alice/Other", "Alice/Other"},
		{"https://github.com/somebody-else/fork", ""}, // not the owner's: cannot be an Expect, still verified and pinned
		{"", ""},
	} {
		t.Run(tc.repo, func(t *testing.T) {
			s := newSigT(t, "", false)
			s.vf.honour = false
			repo := tc.repo
			s.reg.add("alice", "pr-reviewer", "0.2.0", fixtureTar(t, "0.2.0", func(y string) string {
				if repo == "" {
					return y
				}
				return strings.Replace(y, "metadata:", "metadata:\n  repository: \""+repo+"\"", 1)
			}), false)
			s.proxy.set("alice", "pr-reviewer", "0.2.0", 200, fakeSigBytes)
			if code := s.run("pull", "alice/pr-reviewer@0.2.0"); code != 0 {
				t.Fatalf("exit %d: %s", code, s.stderr())
			}
			if got := s.vf.calls[0].want.Repository; got != tc.want {
				t.Errorf("Expect.Repository = %q, want %q", got, tc.want)
			}
			if tc.repo != "" && tc.want == "" && !strings.Contains(s.stderr(), "signature: note: the manifest names repository somebody-else/fork, which is not the repository that signed it") {
				t.Errorf("no note about the differing claim:\n%s", s.stderr())
			}
		})
	}
}

func TestVerifiedRunRecordsOnlyAfterConfirmation(t *testing.T) {
	s := newSigT(t, "n\n", true)
	s.signed()
	if code := s.runArgs("--allow-unenforced-egress", refTarget); code != 1 {
		t.Fatalf("declined run exit %d", code)
	}
	if s.knownFileExists() {
		t.Error("a declined run wrote known.json")
	}
	// The user saw the signature line before being asked.
	if !strings.Contains(s.stderr(), wantVerifiedLine) {
		t.Errorf("stderr:\n%s", s.stderr())
	}
	if s.runner.count() != 0 {
		t.Error("sbx ran")
	}

	s2 := newSigT(t, "y\n", true)
	s2.signed()
	if code := s2.runArgs("--allow-unenforced-egress", refTarget); code != 0 {
		t.Fatalf("confirmed run exit %d: %s", code, s2.stderr())
	}
	if r, _ := s2.rec(t); r.SignerPin == nil || r.SignerPin.RepositoryID != 555 || r.LastRun == nil {
		t.Errorf("record %+v", r)
	}
}

func TestPullDeclinedByRefusalWritesNothingAboutSigner(t *testing.T) {
	s := newSigT(t, "", false)
	s.signed()
	s.vf.err = &sigverify.Error{Kind: sigverify.ErrUntrusted, Detail: "verification failed"}
	if code := s.pull(); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if s.knownFileExists() || s.pulledDirExists() {
		t.Error("a refused pull left state or files")
	}
}

// --- pins ----------------------------------------------------------------

func TestPinnedRepositoryDiffersIsRefusedAndReplaceable(t *testing.T) {
	for _, honour := range []bool{true, false} {
		name := "verifier enforces pins"
		if !honour {
			name = "verifier ignores pins"
		}
		t.Run(name, func(t *testing.T) {
			s := newSigT(t, "", false)
			s.vf.honour = honour
			s.signed()
			s.seed(t, func(r *knownRecord) {
				r.OwnerID = 7
				r.SignerPin = &signerPin{OwnerID: 7, RepositoryID: 111, Repository: "alice/first-repo", VerifiedVersion: "0.0.1"}
			})
			for _, cmd := range []string{"pull", "run"} {
				var code int
				if cmd == "pull" {
					code = s.pull()
				} else {
					code = s.runBundle("--yes")
				}
				e := s.stderr()
				if code != 1 {
					t.Fatalf("%s exit %d: %s", cmd, code, e)
				}
				for _, want := range []string{"alice/first-repo", "alice/pr-reviewer-src", "used to be signed from repository alice/first-repo and is now signed from repository alice/pr-reviewer-src", "--accept-new-signer"} {
					if !strings.Contains(e, want) {
						t.Errorf("%s: refusal lacks %q:\n%s", cmd, want, e)
					}
				}
				assertNoVerifiedClaim(t, e)
				if strings.Contains(e, "signature: verified") {
					t.Error("printed verified for a refused signer")
				}
				if r, _ := s.rec(t); r.SignerPin.RepositoryID != 111 {
					t.Errorf("a refusal changed the pin: %+v", r.SignerPin)
				}
				if s.pulledDirExists() || s.runner.count() != 0 {
					t.Error("work happened after a refusal")
				}
			}
			if code := s.pull("--accept-new-signer"); code != 0 {
				t.Fatalf("exit %d: %s", code, s.stderr())
			}
			if !strings.Contains(s.stderr(), "warning: accepting new signer repository alice/pr-reviewer-src (id 555) for alice/pr-reviewer (was alice/first-repo, id 111)") {
				t.Errorf("no loud acceptance:\n%s", s.stderr())
			}
			if r, _ := s.rec(t); r.SignerPin.RepositoryID != 555 || r.SignerPin.Repository != "alice/pr-reviewer-src" {
				t.Errorf("not re-pinned: %+v", r.SignerPin)
			}
		})
	}
}

func TestRunAcceptNewSignerRepins(t *testing.T) {
	s := newSigT(t, "", false)
	s.signed()
	s.seed(t, func(r *knownRecord) {
		r.OwnerID = 7
		r.SignerPin = &signerPin{OwnerID: 7, RepositoryID: 111, Repository: "alice/first-repo", VerifiedVersion: "0.0.1"}
	})
	if code := s.runBundle("--accept-new-signer"); code != 0 {
		t.Fatalf("exit %d: %s", code, s.stderr())
	}
	if r, _ := s.rec(t); r.SignerPin.RepositoryID != 555 {
		t.Errorf("%+v", r.SignerPin)
	}
}

func TestCertificateOwnerDisagreesWithRegistry(t *testing.T) {
	s := newSigT(t, "", false)
	s.signed()
	s.vf.id.OwnerID = 8 // the registry says 7
	s.vf.honour = false
	if code := s.pull(); code != 1 {
		t.Fatalf("exit %d", code)
	}
	e := s.stderr()
	if !strings.Contains(e, "the registry and the signature disagree about who owns alice/pr-reviewer (the registry reports owner id 7, the signing certificate says 8)") {
		t.Errorf("stderr:\n%s", e)
	}
	if s.knownFileExists() || s.pulledDirExists() {
		t.Error("state or files written")
	}
	assertNoVerifiedClaim(t, e)
	if code := s.pull("--accept-new-owner", "--accept-new-signer"); code != 1 {
		t.Errorf("the pin overrides must not hide a registry/certificate disagreement (exit %d)", code)
	}
}

func TestRegistryWithoutOwnerIdSkipsCrossCheckAndPinsFromCertificate(t *testing.T) {
	s := newSigT(t, "", false)
	s.reg.ownerID = 0 // an older registry reports none
	s.signed()
	if code := s.pull(); code != 0 {
		t.Fatalf("exit %d: %s", code, s.stderr())
	}
	if strings.Contains(s.stderr(), "did not report an owner id") {
		t.Errorf("a verified signature supplies the id; no warning expected:\n%s", s.stderr())
	}
	if r, _ := s.rec(t); r.OwnerID != 7 || r.SignerPin == nil || r.SignerPin.OwnerID != 7 {
		t.Errorf("record %+v", r)
	}
}

func TestOrganisationBundleOwnerIdAgrees(t *testing.T) {
	s := newSigT(t, "", false)
	// An organisation bundle: the registry reports the organisation's id and
	// the workflow in an organisation repository signs with that same id.
	s.reg.add("acme", "agent", "1.0.0", testBundleTar(t, "agent", "1.0.0"), false)
	s.reg.ownerID = 900
	s.proxy.set("acme", "agent", "1.0.0", 200, fakeSigBytes)
	s.vf.id = sigverify.Identity{Issuer: sigverify.ActionsIssuer, OwnerLogin: "acme", OwnerID: 900, Repository: "acme/agent-src", RepositoryID: 31,
		WorkflowRef: "https://github.com/acme/agent-src/.github/workflows/p.yml@refs/heads/main", SourceSHA: strings.Repeat("a", 40)}
	if code := s.run("pull", "acme/agent@1.0.0"); code != 0 {
		t.Fatalf("exit %d: %s", code, s.stderr())
	}
	if !strings.Contains(s.stderr(), "signature: verified — signed by a GitHub Actions workflow in acme/agent-src") {
		t.Errorf("stderr:\n%s", s.stderr())
	}
	// Signed from a member's personal repository: not the organisation.
	s2 := newSigT(t, "", false)
	s2.reg.add("acme", "agent", "1.0.0", testBundleTar(t, "agent", "1.0.0"), false)
	s2.reg.ownerID = 900
	s2.proxy.set("acme", "agent", "1.0.0", 200, fakeSigBytes)
	s2.vf.id = sigverify.Identity{OwnerLogin: "member", OwnerID: 12, Repository: "member/fork", RepositoryID: 32, WorkflowRef: "x"}
	if code := s2.run("pull", "acme/agent@1.0.0"); code != 1 {
		t.Fatalf("exit %d: %s", code, s2.stderr())
	}
	if !strings.Contains(s2.stderr(), "made for a different owner or repository") {
		t.Errorf("stderr:\n%s", s2.stderr())
	}
}

func TestPinnedOwnerIdConflictUsesOwnerChangedRefusal(t *testing.T) {
	for _, honour := range []bool{true, false} {
		s := newSigT(t, "", false)
		s.vf.honour = honour
		s.signed()
		s.seed(t, func(r *knownRecord) { r.OwnerID = 5 }) // pinned from an earlier unsigned run
		for _, cmd := range []string{"pull", "run"} {
			var code int
			if cmd == "pull" {
				code = s.pull()
			} else {
				code = s.runBundle()
			}
			e := s.stderr()
			if code != 1 || !strings.Contains(e, "its owner changed") || !strings.Contains(e, "--accept-new-owner") || !strings.Contains(e, "pinned owner id") {
				t.Fatalf("%s honour=%v exit %d:\n%s", cmd, honour, code, e)
			}
			if strings.Contains(e, "signature: verified") || s.pulledDirExists() {
				t.Error("verified/pulled on an owner change")
			}
		}
		if r, _ := s.rec(t); r.OwnerID != 5 || r.SignerPin != nil {
			t.Errorf("refusal changed the record: %+v", r)
		}
		if code := s.pull("--accept-new-owner"); code != 0 {
			t.Fatalf("accept: exit %d: %s", code, s.stderr())
		}
		r, _ := s.rec(t)
		if r.OwnerID != 7 || r.SignerPin == nil || r.SignerPin.OwnerID != 7 {
			t.Errorf("not re-pinned: %+v", r)
		}
	}
}

func TestOwnerChangeAcceptedDropsTheOldRepositoryPin(t *testing.T) {
	s := newSigT(t, "", false)
	s.signed()
	s.seed(t, func(r *knownRecord) {
		r.OwnerID = 5
		r.SignerPin = &signerPin{OwnerID: 5, RepositoryID: 111, Repository: "old/repo", VerifiedVersion: "0.0.1"}
	})
	if code := s.pull("--accept-new-owner"); code != 0 {
		t.Fatalf("exit %d: %s", code, s.stderr())
	}
	if r, _ := s.rec(t); r.OwnerID != 7 || r.SignerPin.RepositoryID != 555 {
		t.Errorf("%+v / %+v", r, r.SignerPin)
	}
}

// --- failures ------------------------------------------------------------

func TestStaleTrustRootRefusesWithUpdateHint(t *testing.T) {
	for _, tc := range []struct{ name, exe, hint string }{
		{"plain", "/usr/local/bin/capm", "run capm self-update"},
		{"homebrew", "/opt/homebrew/Cellar/capm/1.2.3/bin/capm", "run brew upgrade capm"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSigT(t, "", false)
			s.signed()
			s.vf.err = &sigverify.StaleTrustRootError{Reason: "x"}
			s.env.upd.exePath = func() (string, error) { return tc.exe, nil }
			for _, cmd := range []string{"pull", "run"} {
				var code int
				if cmd == "pull" {
					code = s.pull()
				} else {
					code = s.runBundle("--yes")
				}
				e := s.stderr()
				if code != 1 {
					t.Fatalf("%s exit %d", cmd, code)
				}
				for _, want := range []string{
					"this version of capm cannot check this signature because its built-in trust material is out of date or does not cover the signer",
					"To fix this, " + tc.hint + " and try again",
					"capm will not treat the version as unsigned",
				} {
					if !strings.Contains(e, want) {
						t.Errorf("%s: lacks %q:\n%s", cmd, want, e)
					}
				}
				if strings.Contains(e, wantUnsignedLine) {
					t.Error("fell back to unsigned")
				}
				assertNoVerifiedClaim(t, e)
			}
			if s.knownFileExists() || s.pulledDirExists() || s.runner.count() != 0 {
				t.Error("state, files or sandbox after a stale-root refusal")
			}
		})
	}
}

func TestVerificationFailuresRefuseWithBroadReasonOnly(t *testing.T) {
	const evil = "EVIL\x1b[31m-attacker-text"
	idErr := func(field, reason string) error {
		return &sigverify.IdentityError{Field: field, Reason: reason, Want: evil, Got: evil}
	}
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"untrusted", &sigverify.Error{Kind: sigverify.ErrUntrusted, Detail: "verification failed", Err: errors.New(evil)}, "does not match this download, or its certificate or transparency-log proof did not check out"},
		{"malformed", &sigverify.Error{Kind: sigverify.ErrMalformed, Detail: "cannot parse bundle", Err: errors.New(evil)}, "malformed or not in a format capm accepts"},
		{"not actions", idErr("issuer", "mismatch"), "not made by a GitHub Actions workflow of the kind capm accepts"},
		{"bad workflow", idErr("workflow", "malformed"), "not made by a GitHub Actions workflow of the kind capm accepts"},
		{"other owner", idErr("owner login", "mismatch"), "made for a different owner or repository than this bundle's"},
		{"other repo", idErr("repository", "mismatch"), "made for a different owner or repository than this bundle's"},
		{"invalid input", sigverify.ErrInvalidInput, "could not be checked"},
		{"mystery", errors.New(evil), "could not be checked"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSigT(t, "", false)
			s.signed()
			s.vf.err = tc.err
			for _, cmd := range []string{"pull", "run"} {
				var code int
				if cmd == "pull" {
					code = s.pull()
				} else {
					code = s.runBundle("--yes") // --yes never bypasses a refusal
				}
				e := s.stderr()
				if code != 1 {
					t.Fatalf("%s exit %d: %s", cmd, code, e)
				}
				if !strings.Contains(e, "refusing alice/pr-reviewer@0.1.0: the signature attached to it did not verify: it ") || !strings.Contains(e, tc.want) {
					t.Errorf("%s stderr:\n%s", cmd, e)
				}
				if !strings.Contains(e, "--allow-invalid-signature") {
					t.Errorf("%s: no override named:\n%s", cmd, e)
				}
				if strings.Contains(e, "EVIL") || strings.Contains(e, "attacker") || strings.Contains(e, "\x1b") {
					t.Errorf("%s echoed attacker-controlled text:\n%q", cmd, e)
				}
				assertNoVerifiedClaim(t, e)
			}
			if s.knownFileExists() || s.pulledDirExists() || s.runner.count() != 0 {
				t.Error("state, files or sandbox after a refusal")
			}
		})
	}
}

func TestAllowInvalidSignatureProceedsAsUnsignedAndRecordsNothingSigned(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"untrusted", &sigverify.Error{Kind: sigverify.ErrUntrusted}},
		{"stale", &sigverify.StaleTrustRootError{Reason: "x"}},
	} {
		for _, cmd := range []string{"pull", "run"} {
			t.Run(tc.name+"/"+cmd, func(t *testing.T) {
				s := newSigT(t, "", false)
				s.signed()
				s.vf.err = tc.err
				s.seed(t, func(r *knownRecord) {
					r.OwnerID = 7
					r.SignerPin = &signerPin{OwnerID: 7, RepositoryID: 111, Repository: "alice/first-repo", VerifiedVersion: "0.0.1"}
				})
				var code int
				if cmd == "pull" {
					code = s.pull("--allow-invalid-signature")
				} else {
					code = s.runBundle("--allow-invalid-signature")
				}
				if code != 0 {
					t.Fatalf("exit %d: %s", code, s.stderr())
				}
				e := s.stderr()
				if !strings.Contains(e, "warning: --allow-invalid-signature: continuing although this version's signature could not be accepted") ||
					!strings.Contains(e, "treating alice/pr-reviewer@0.1.0 as UNSIGNED") {
					t.Errorf("no loud warning:\n%s", e)
				}
				assertNoVerifiedClaim(t, e)
				r, _ := s.rec(t)
				if r.SignerPin == nil || r.SignerPin.RepositoryID != 111 || r.SignerPin.VerifiedVersion != "0.0.1" {
					t.Errorf("an overridden signature changed the signer pin: %+v", r.SignerPin)
				}
			})
		}
	}
}

func TestAllowInvalidSignatureNeverRecordsVerified(t *testing.T) {
	s := newSigT(t, "", false)
	s.signed()
	s.vf.err = &sigverify.Error{Kind: sigverify.ErrUntrusted}
	if code := s.runBundle("--allow-invalid-signature"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if r, _ := s.rec(t); r.SignerPin != nil {
		t.Errorf("recorded a signer: %+v", r.SignerPin)
	}
}

func TestOverrideFlagIsFlagOnly(t *testing.T) {
	// There is no environment-variable override: setting plausible names does nothing.
	s := newSigT(t, "", false)
	s.signed()
	s.vf.err = &sigverify.Error{Kind: sigverify.ErrUntrusted}
	for _, k := range []string{"CAPM_ALLOW_INVALID_SIGNATURE", "CAPM_ALLOW_UNSIGNED", "CAPM_INSECURE"} {
		t.Setenv(k, "1")
	}
	s.vars["CAPM_ALLOW_INVALID_SIGNATURE"] = "1"
	if code := s.runBundle(); code != 1 {
		t.Fatalf("exit %d", code)
	}
}

func TestSignatureFetchFailures(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body []byte
		ok   bool
	}{
		{"500", 500, []byte(`{"error":"boom"}`), false},
		{"503", 503, nil, false},
		{"403", 403, nil, false},
		{"oversized", 200, bytes.Repeat([]byte("a"), 65537), false},
		{"404 is unsigned", 404, []byte(`{"error":"no signature"}`), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newSigT(t, "", false)
			s.proxy.set("alice", "pr-reviewer", "0.1.0", tc.code, tc.body)
			code := s.runBundle()
			e := s.stderr()
			if tc.ok {
				if code != 0 || !strings.Contains(e, wantUnsignedLine) {
					t.Fatalf("exit %d:\n%s", code, e)
				}
				return
			}
			if code != 1 {
				t.Fatalf("exit %d:\n%s", code, e)
			}
			if !strings.Contains(e, "could not fetch its signature") || !strings.Contains(e, "Only a missing signature (404) counts as unsigned") || !strings.Contains(e, "--allow-invalid-signature") {
				t.Errorf("stderr:\n%s", e)
			}
			if strings.Contains(e, wantUnsignedLine) || s.vf.callCount() != 0 || s.runner.count() != 0 {
				t.Error("treated as unsigned, or verified, or ran")
			}
			assertNoVerifiedClaim(t, e)
			// The override continues as unsigned and says so loudly.
			if code := s.runBundle("--allow-invalid-signature"); code != 0 {
				t.Fatalf("override exit %d:\n%s", code, s.stderr())
			}
			if !strings.Contains(s.stderr(), "treating alice/pr-reviewer@0.1.0 as UNSIGNED") {
				t.Errorf("override not loud:\n%s", s.stderr())
			}
		})
	}
}

func TestSignatureTransportFailureRefuses(t *testing.T) {
	s := newSigT(t, "", false)
	// Everything works except the signature request, which dies mid-connection.
	s.proxy.set("alice", "pr-reviewer", "0.1.0", dropConnection, nil)
	if code := s.pull(); code != 1 {
		t.Fatalf("exit %d: %s", code, s.stderr())
	}
	if !strings.Contains(s.stderr(), "could not fetch its signature") || strings.Contains(s.stderr(), wantUnsignedLine) {
		t.Errorf("stderr:\n%s", s.stderr())
	}
	assertNoVerifiedClaim(t, s.stderr())
	if s.pulledDirExists() || s.knownFileExists() {
		t.Error("work or state after a refusal")
	}
}

func TestSignatureRequestsCarryNoCredentials(t *testing.T) {
	s := newSigT(t, "", false)
	s.signed()
	if err := os.MkdirAll(s.env.credDir, 0o700); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(s.env.credDir, "credentials.json"), []byte(`{"registries":{}}`), 0o600)
	if code := s.pull(); code != 0 {
		t.Fatalf("exit %d: %s", code, s.stderr())
	}
	s.proxy.mu.Lock()
	defer s.proxy.mu.Unlock()
	for _, a := range s.proxy.auth {
		if a != "" {
			t.Errorf("Authorization sent with a signature request: %q", a)
		}
	}
}

// --- manifest identity before signature ---------------------------------

func TestManifestMismatchIsRefusedBeforeAnySignatureRequest(t *testing.T) {
	s := newSigT(t, "", false)
	s.reg.add("alice", "pr-reviewer", "0.3.0", fixtureTar(t, "0.1.0", nil), false) // manifest says 0.1.0
	s.proxy.set("alice", "pr-reviewer", "0.3.0", 200, fakeSigBytes)
	if code := s.run("pull", "alice/pr-reviewer@0.3.0"); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if sig, _ := s.proxy.counts(); sig != 0 || s.vf.callCount() != 0 {
		t.Errorf("a signature was requested (%d) or verified for a bundle that is not the one asked for", sig)
	}
}

// --- --yes does not bypass refusals -------------------------------------

func TestYesDoesNotBypassVerifiedRefusals(t *testing.T) {
	s := newSigT(t, "", false)
	s.signed()
	s.seed(t, func(r *knownRecord) {
		r.OwnerID = 7
		r.SignerPin = &signerPin{OwnerID: 7, RepositoryID: 111, Repository: "alice/first-repo", VerifiedVersion: "0.0.1"}
	})
	if code := s.runArgs("--yes", "-y", "--allow-unenforced-egress", "--accept-permission-changes", "--accept-changed-digest", refTarget); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if s.runner.count() != 0 {
		t.Error("sbx ran")
	}
}

func TestYesRunsVerifiedAndUnsignedBundles(t *testing.T) {
	s := newSigT(t, "", false)
	s.signed()
	if code := s.runBundle(); code != 0 {
		t.Fatalf("verified exit %d: %s", code, s.stderr())
	}
	u := newSigT(t, "", false)
	if code := u.runBundle(); code != 0 {
		t.Fatalf("unsigned exit %d: %s", code, u.stderr())
	}
}

// --- ordering -----------------------------------------------------------

func TestSignatureLineAppearsBeforeConfirmation(t *testing.T) {
	s := newSigT(t, "n\n", true)
	s.signed()
	s.runArgs("--allow-unenforced-egress", refTarget)
	if !strings.Contains(s.stderr(), "signature: verified") || !strings.Contains(s.out.String(), "Proceed? [y/N]") {
		t.Fatalf("stdout:\n%s\nstderr:\n%s", s.out.String(), s.stderr())
	}
}

func TestSignatureCheckedBeforeOwnerPinning(t *testing.T) {
	// A bad signature on a bundle whose owner also changed reports the
	// signature problem first (digest -> manifest -> signature -> owner).
	s := newSigT(t, "", false)
	s.signed()
	s.seed(t, func(r *knownRecord) { r.OwnerID = 5 })
	s.vf.err = &sigverify.Error{Kind: sigverify.ErrUntrusted}
	s.pull()
	if !strings.Contains(s.stderr(), "did not verify") || strings.Contains(s.stderr(), "its owner changed") {
		t.Errorf("stderr:\n%s", s.stderr())
	}
}

// --- local directories --------------------------------------------------

func TestLocalDirectoriesMakeNoSignatureRequest(t *testing.T) {
	s := newSigT(t, "", false)
	s.signed()
	if code := s.runArgs("--yes", "--allow-unenforced-egress", fixtureAbs); code != 0 {
		t.Fatalf("run exit %d: %s", code, s.stderr())
	}
	if strings.Contains(s.stderr(), "signature") {
		t.Errorf("signature logic ran for a local run:\n%s", s.stderr())
	}
	if code := s.run("inspect", fixtureAbs); code != 0 {
		t.Fatalf("inspect exit %d: %s", code, s.stderr())
	}
	if strings.Contains(s.stderr(), "signature") {
		t.Errorf("signature logic ran for a local inspect:\n%s", s.stderr())
	}
	if sig, all := s.proxy.counts(); sig != 0 || all != 0 {
		t.Errorf("a local directory made %d signature and %d total requests", sig, all)
	}
	if s.vf.callCount() != 0 {
		t.Error("the verifier ran for a local directory")
	}
	if s.knownFileExists() {
		t.Error("local run wrote known.json")
	}
}

// --- the real verifier ---------------------------------------------------

func TestDefaultEnvUsesTheRealVerifier(t *testing.T) {
	got := reflect.ValueOf(env{}.verifier()).Pointer()
	want := reflect.ValueOf(sigverify.Verify).Pointer()
	if got != want {
		t.Fatal("the default env does not call sigverify.Verify")
	}
}

// The only real GitHub Actions bundle available offline is a v0.1 DSSE
// attestation, which production Verify refuses (see internal/sigverify's
// README). Wiring it through the CLI proves the real verifier is what runs and
// that a real signature the policy does not accept BLOCKS rather than passes.
func TestRealVerifierRefusesTheRealButUnacceptableFixture(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join(fixtureAbs, "..", "..", "internal", "sigverify", "testdata", "sigstore.js@2.0.0-provenance.sigstore.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"pull", "run", "inspect"} {
		t.Run(cmd, func(t *testing.T) {
			s := newSigT(t, "", false)
			s.env.verify = nil // the default: sigverify.Verify
			s.proxy.set("alice", "pr-reviewer", "0.1.0", 200, fixture)
			s.reg.metaExtra = map[string]any{"signed": true}
			var code int
			switch cmd {
			case "pull":
				code = s.pull()
			case "run":
				code = s.runBundle()
			default:
				code = s.run("inspect", refTarget)
			}
			e := s.stderr()
			if code != 1 {
				t.Fatalf("exit %d:\n%s", code, e)
			}
			if !strings.Contains(e, "did not verify: it is malformed or not in a format capm accepts") {
				t.Errorf("not refused for the documented reason (older bundle format):\n%s", e)
			}
			if strings.Contains(e, "signature: verified") || strings.Contains(e, "signature: valid") {
				t.Error("claimed success for a signature production Verify refuses")
			}
			assertNoVerifiedClaim(t, e)
			if s.pulledDirExists() || s.runner.count() != 0 || s.knownFileExists() {
				t.Error("work or state after a refusal")
			}
		})
	}
}

// --- success-only wording ------------------------------------------------

func TestVerifiedAndValidAreOnlyPrintedOnSuccessPaths(t *testing.T) {
	type scenario struct {
		name  string
		setup func(*sigT)
		code  int
		ok    bool // a success path
	}
	scs := []scenario{
		{"unsigned", func(s *sigT) {}, 0, false}, // success, but of an unsigned bundle
		{"verified", func(s *sigT) { s.signed() }, 0, true},
		{"fetch 500", func(s *sigT) { s.proxy.set("alice", "pr-reviewer", "0.1.0", 500, nil) }, 1, false},
		{"untrusted", func(s *sigT) { s.signed(); s.vf.err = &sigverify.Error{Kind: sigverify.ErrUntrusted} }, 1, false},
		{"stale", func(s *sigT) { s.signed(); s.vf.err = &sigverify.StaleTrustRootError{Reason: "x"} }, 1, false},
		{"identity", func(s *sigT) { s.signed(); s.vf.err = &sigverify.IdentityError{Field: "issuer", Reason: "mismatch"} }, 1, false},
		{"malformed", func(s *sigT) { s.signed(); s.vf.err = &sigverify.Error{Kind: sigverify.ErrMalformed} }, 1, false},
		{"override", func(s *sigT) { s.signed(); s.vf.err = &sigverify.Error{Kind: sigverify.ErrUntrusted} }, 0, false},
	}
	for _, sc := range scs {
		t.Run(sc.name, func(t *testing.T) {
			s := newSigT(t, "", false)
			sc.setup(s)
			args := []string{}
			if sc.name == "override" {
				args = append(args, "--allow-invalid-signature")
			}
			if code := s.pull(args...); code != sc.code {
				t.Fatalf("exit %d: %s", code, s.stderr())
			}
			e := s.stderr()
			has := strings.Contains(e, "signature: verified")
			if has != sc.ok {
				t.Errorf("'signature: verified' present=%v, want %v:\n%s", has, sc.ok, e)
			}
			if !sc.ok {
				assertNoVerifiedClaim(t, e)
			}
		})
	}
}

func TestKnownListsSignerAndForgetClearsIt(t *testing.T) {
	s := newSigT(t, "", false)
	s.signed()
	if code := s.pull(); code != 0 {
		t.Fatalf("exit %d: %s", code, s.stderr())
	}
	if code := s.run("known"); code != 0 {
		t.Fatal(code)
	}
	if out := s.out.String(); !strings.Contains(out, "SIGNER") || !strings.Contains(out, "alice/pr-reviewer-src (verified 0.1.0)") {
		t.Errorf("known:\n%s", out)
	}
	if code := s.run("known", "forget", "alice/pr-reviewer"); code != 0 {
		t.Fatal(code)
	}
	if _, ok := s.rec(t); ok {
		t.Error("forget left the record, including the signer pin")
	}
	b, _ := os.ReadFile(filepath.Join(s.env.credDir, knownFileName))
	if strings.Contains(string(b), "signerPin") {
		t.Errorf("signer pin survived forget:\n%s", b)
	}
}
