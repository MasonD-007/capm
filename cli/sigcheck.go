package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/MasonD-007/capm/cli/internal/client"
	"github.com/MasonD-007/capm/cli/internal/sigverify"
	"github.com/MasonD-007/capm/manifest"
)

// Signature checking for pull, run and inspect.
//
// The cryptography is internal/sigverify's. This file decides what to do with
// its answer, and it follows two rules:
//
//   - Nothing is described as verified unless sigverify.Verify returned nil for
//     this exact download (or, in inspect, for the digest the registry
//     reports, and then it says so).
//   - Anything unexpected refuses. Only a clean 404 for the signature means
//     "this version is unsigned".

// verifyFunc has the shape of sigverify.Verify. env.verify replaces it in tests
// only; there is no way to set it from the command line or the environment.
type verifyFunc func(sigBundle, digest []byte, want sigverify.Expect) (sigverify.Identity, error)

func (e env) verifier() verifyFunc {
	if e.verify != nil {
		return e.verify
	}
	return sigverify.Verify
}

// sigFlags are the overrides of pull and run.
type sigFlags struct {
	acceptNewOwner  bool // reuses the owner-pinning override
	acceptNewSigner bool
	allowInvalid    bool
}

const (
	unsignedLine = "signature: none (this version is unsigned; its publisher is identified only by the registry)"
	overrideHint = "pass --allow-invalid-signature to continue as if it were unsigned; nothing will be recorded as signed"
)

// sigOutcome is what the signature stage learned.
type sigOutcome struct {
	// verified is true only when sigverify accepted a signature over exactly
	// the bytes that were downloaded; id is then the verified identity.
	verified bool
	id       sigverify.Identity
}

// ownerID is the owner id to pin and compare: the certificate's when a
// signature was verified (the cross-check has already made it agree with the
// registry's, when the registry reports one), else the registry's.
func (o sigOutcome) ownerID(registryID int64) int64 {
	if o.verified {
		return o.id.OwnerID
	}
	return registryID
}

// record stores the signer pin in r. It does nothing unless a signature was
// verified, so an unsigned or overridden run never changes it.
func (o sigOutcome) record(r *knownRecord, version string) {
	if !o.verified {
		return
	}
	p := &signerPin{
		OwnerID: o.id.OwnerID, RepositoryID: o.id.RepositoryID, Repository: o.id.Repository,
		VerifiedVersion: version, At: time.Now().UTC(),
	}
	if r.SignerPin != nil {
		p.extra = r.SignerPin.extra
	}
	r.SignerPin = p
}

// sigStage is the input of checkSignature.
type sigStage struct {
	cmd         string
	stderr      io.Writer
	owner, name string
	res         client.Resolved
	digest      [sha256.Size]byte // of the bytes capm downloaded
	m           *manifest.Manifest
	rec         knownRecord
	recorded    bool
	flags       sigFlags
}

func (s sigStage) ref() string { return s.owner + "/" + s.name + "@" + s.res.Version }

func (s sigStage) refuse(format string, a ...any) (sigOutcome, bool) {
	fmt.Fprintf(s.stderr, "capm %s: "+format+"\n", append([]any{s.cmd}, a...)...)
	return sigOutcome{}, false
}

// checkSignature runs after the digest and manifest checks. It prints the
// signature line(s) and returns ok=false (after printing why) when the command
// must stop. It never writes known.json: the caller records the outcome when
// it is entitled to.
func (e env) checkSignature(s sigStage) (sigOutcome, bool) {
	sig, found, err := client.New(e.registry, "").FetchSignature(s.owner, s.name, s.res.Version)
	if err != nil {
		if s.flags.allowInvalid {
			s.warnOverride("its signature could not be fetched (" + client.Sanitize(err.Error()) + ")")
			return sigOutcome{}, true
		}
		return s.refuse("refusing %s: could not fetch its signature: %s\n"+
			"Only a missing signature (404) counts as unsigned; any other failure stops here so that a signed version cannot be made to look unsigned by blocking the request.\n"+
			"Try again, or %s.", s.ref(), client.Sanitize(err.Error()), overrideHint)
	}
	if !found {
		fmt.Fprintln(s.stderr, unsignedLine)
		s.noteEarlierSigned()
		return sigOutcome{}, true
	}

	expect := sigverify.Expect{OwnerLogin: s.owner, Repository: s.manifestRepository()}
	if s.recorded {
		expect.OwnerID = s.rec.OwnerID
		if s.rec.SignerPin != nil {
			expect.RepositoryID = s.rec.SignerPin.RepositoryID
		}
	}
	id, err := e.verifyLearning(sig, s.digest[:], expect)
	if err != nil {
		reason, stale := e.failureReason(err)
		if s.flags.allowInvalid {
			s.warnOverride(reason)
			return sigOutcome{}, true
		}
		if stale {
			return s.refuse("refusing %s: %s. %s", s.ref(), reason, e.staleFix())
		}
		return s.refuse("refusing %s: the signature attached to it did not verify: %s.\nIf you understand the risk, %s.", s.ref(), reason, overrideHint)
	}
	// Belt and braces: whatever the verifier did with the expectations, the
	// identity it returned must satisfy them.
	if !strings.EqualFold(id.OwnerLogin, s.owner) || id.OwnerID <= 0 || id.RepositoryID <= 0 || id.Repository == "" {
		return s.refuse("refusing %s: the signature attached to it did not verify: its identity is incomplete.\nIf you understand the risk, %s.", s.ref(), overrideHint)
	}

	// The registry and the certificate must agree about who owns this name.
	// Organisation bundles agree too: the registry reports the organisation's
	// id and a workflow in an organisation repository signs with the
	// organisation's id as its repository owner id. An id of 0 means the
	// registry did not report one (an older server), and there is nothing to
	// compare.
	if s.res.OwnerID > 0 && s.res.OwnerID != id.OwnerID {
		reason := fmt.Sprintf("the registry and the signature disagree about who owns %s/%s (the registry reports owner id %d, the signing certificate says %d)", s.owner, s.name, s.res.OwnerID, id.OwnerID)
		if s.flags.allowInvalid {
			s.warnOverride(reason)
			return sigOutcome{}, true
		}
		return s.refuse("refusing %s: %s. capm cannot tell which is right, so it will not use this version.\nIf you understand the risk, %s.", s.ref(), reason, overrideHint)
	}

	ownerChanged := s.recorded && s.rec.OwnerID > 0 && id.OwnerID != s.rec.OwnerID
	if ownerChanged && !s.flags.acceptNewOwner {
		// The same refusal, and the same override, as owner pinning.
		fmt.Fprintf(s.stderr, "capm %s: %s\n", s.cmd, newOwnerRefusal(s.owner, s.name, pinInfo{state: pinChanged, pinned: s.rec.OwnerID, current: id.OwnerID}))
		return sigOutcome{}, false
	}
	// A different owner has different repositories; the owner check above is
	// the one that matters then, so the repository pin is not compared.
	if !ownerChanged && s.recorded && s.rec.SignerPin != nil && s.rec.SignerPin.RepositoryID > 0 && id.RepositoryID != s.rec.SignerPin.RepositoryID {
		p := s.rec.SignerPin
		if !s.flags.acceptNewSigner {
			return s.refuse("refusing %s/%s: the repository that signs it changed.\n"+
				"  signer repository you pinned (from the first signed version you used): %s (id %d)\n"+
				"  repository that signed this version:                                    %s (id %d)\n"+
				"This bundle used to be signed from repository %s and is now signed from repository %s. A signature binds a bundle to one repository, so a change is treated like a change of publisher. "+
				"If you trust the new repository, run again with --accept-new-signer to proceed and pin it.",
				s.owner, s.name, client.Sanitize(p.Repository), p.RepositoryID, id.Repository, id.RepositoryID, client.Sanitize(p.Repository), id.Repository)
		}
		fmt.Fprintf(s.stderr, "warning: accepting new signer repository %s (id %d) for %s/%s (was %s, id %d)\n",
			id.Repository, id.RepositoryID, s.owner, s.name, client.Sanitize(p.Repository), p.RepositoryID)
	}

	fmt.Fprintln(s.stderr, verifiedLine(id))
	if s.m != nil {
		if o, r, ok := manifest.ParseRepository(s.m.Metadata.Repository); ok && !strings.EqualFold(o+"/"+r, id.Repository) {
			fmt.Fprintf(s.stderr, "signature: note: the manifest names repository %s/%s, which is not the repository that signed it\n", o, r)
		}
	}
	switch p := s.rec.SignerPin; {
	case !s.recorded || p == nil:
		fmt.Fprintf(s.stderr, "signature: first signed version of this bundle seen on this machine; its signer, repository %s (id %d), is pinned from now on\n", id.Repository, id.RepositoryID)
	case p.RepositoryID == id.RepositoryID && !ownerChanged:
		fmt.Fprintf(s.stderr, "signature: signed from the repository you pinned (%s)\n", id.Repository)
	}
	return sigOutcome{verified: true, id: id}, true
}

// verifyLearning calls the verifier with the pinned ids in expect. If it fails
// only because a pinned id differs, it asks again without the pins so that the
// caller learns the verified identity and can say exactly what changed (and
// honour --accept-new-owner / --accept-new-signer). The caller compares the
// returned identity with the pins itself either way.
func (e env) verifyLearning(sig, digest []byte, expect sigverify.Expect) (sigverify.Identity, error) {
	verify := e.verifier()
	id, err := verify(sig, digest, expect)
	var ie *sigverify.IdentityError
	if err != nil && errors.As(err, &ie) && ie.Reason == "mismatch" && (ie.Field == "owner id" || ie.Field == "repository id") {
		expect.OwnerID, expect.RepositoryID = 0, 0
		id, err = verify(sig, digest, expect)
	}
	return id, err
}

// manifestRepository is the manifest's metadata.repository as owner/repo, but
// only when it belongs to the bundle's owner: sigverify refuses an expectation
// naming another owner, and a bundle may legitimately point at somebody else's
// repository. The identity is still pinned, and a differing claim is noted.
func (s sigStage) manifestRepository() string {
	if s.m == nil {
		return ""
	}
	o, r, ok := manifest.ParseRepository(s.m.Metadata.Repository)
	if !ok || !strings.EqualFold(o, s.owner) {
		return ""
	}
	return o + "/" + r
}

// noteEarlierSigned says so when a version of this bundle that capm verified
// earlier was signed and this one is not. It is information, never a refusal.
func (s sigStage) noteEarlierSigned() {
	if !s.recorded || s.rec.SignerPin == nil || s.rec.SignerPin.VerifiedVersion == "" {
		return
	}
	p := s.rec.SignerPin
	if p.VerifiedVersion == s.res.Version {
		fmt.Fprintf(s.stderr, "signature: note: you used this same version before, when it was signed from %s, and the registry now has no signature for it\n", client.Sanitize(p.Repository))
		return
	}
	fmt.Fprintf(s.stderr, "signature: note: version %s, which you used earlier, was signed from %s; this version is not signed. A later unsigned version is not blocked, so check why before relying on it.\n",
		client.Sanitize(p.VerifiedVersion), client.Sanitize(p.Repository))
}

// warnOverride is the loud line printed when --allow-invalid-signature lets a
// run continue.
func (s sigStage) warnOverride(reason string) {
	fmt.Fprintf(s.stderr, "warning: --allow-invalid-signature: continuing although this version's signature could not be accepted (%s).\n"+
		"warning: capm is treating %s as UNSIGNED: nothing about who published it was checked, and nothing will be recorded as signed or pinned.\n", reason, s.ref())
}

// verifiedLine is printed only after Verify succeeded on the downloaded bytes.
func verifiedLine(id sigverify.Identity) string {
	detail := client.Sanitize(id.WorkflowRef)
	if sha := id.SourceSHA; sha != "" {
		if len(sha) > 7 {
			sha = sha[:7]
		}
		if detail != "" {
			detail += ", "
		}
		detail += "commit " + client.Sanitize(sha)
	}
	if detail != "" {
		detail = " (" + detail + ")"
	}
	return "signature: verified — signed by a GitHub Actions workflow in " + client.Sanitize(id.Repository) + detail
}

// staleFix is the sentence that follows a stale-trust-root refusal. The advice
// is the update notice's: brew for a Homebrew install, self-update otherwise.
func (e env) staleFix() string {
	advice := e.updateAdvice()
	if rest, ok := strings.CutPrefix(advice, "update it "); ok {
		advice = "update capm " + rest
	}
	return "To fix this, " + advice + " and try again. capm will not treat the version as unsigned."
}

// failureReason turns a Verify error into text that names the broad reason
// without echoing anything the signature's author controls. stale is true for
// ErrStaleTrustRoot, whose message is a complete sentence.
func (e env) failureReason(err error) (reason string, stale bool) {
	var ie *sigverify.IdentityError
	switch {
	case errors.Is(err, sigverify.ErrStaleTrustRoot):
		return "this version of capm cannot check this signature because its built-in trust material is out of date or does not cover the signer", true
	case errors.As(err, &ie):
		switch ie.Field {
		case "owner login", "owner id", "repository", "repository id":
			if ie.Reason == "mismatch" {
				return "it was made for a different owner or repository than this bundle's", false
			}
		}
		return "it was not made by a GitHub Actions workflow of the kind capm accepts", false
	case errors.Is(err, sigverify.ErrUntrusted):
		return "it does not match this download, or its certificate or transparency-log proof did not check out", false
	case errors.Is(err, sigverify.ErrMalformed):
		return "it is malformed or not in a format capm accepts", false
	}
	return "it could not be checked", false
}

// inspectSignature is the signature part of `capm inspect owner/name`. The
// bundle is not downloaded, so a verified signature proves only that it covers
// the digest the registry reports. It prints to stderr and returns false when
// inspect must exit 1. It never writes anything.
func (e env) inspectSignature(c *client.Client, stderr io.Writer, owner, name string, res client.Resolved, md client.Metadata, signed bool, rec knownRecord, recorded bool) bool {
	ref := owner + "/" + name + "@" + res.Version
	fail := func(format string, a ...any) bool {
		fmt.Fprintf(stderr, "capm inspect: "+format+"\n", a...)
		return false
	}
	if !signed {
		fmt.Fprintln(stderr, "signature: none reported by the registry (capm has checked nothing; an unsigned version's publisher is identified only by the registry)")
		if recorded && rec.SignerPin != nil && rec.SignerPin.Repository != "" {
			fmt.Fprintf(stderr, "signer pin: you pinned %s (repository id %d) when you used version %s, which was signed; this version is not\n",
				client.Sanitize(rec.SignerPin.Repository), rec.SignerPin.RepositoryID, client.Sanitize(rec.SignerPin.VerifiedVersion))
		}
		return true
	}
	sig, found, err := c.FetchSignature(owner, name, res.Version)
	switch {
	case err != nil:
		return fail("the registry says %s is signed but its signature could not be fetched: %s", ref, client.Sanitize(err.Error()))
	case !found:
		return fail("the registry says %s is signed but serves no signature for it", ref)
	}
	hexDigest, ok := strings.CutPrefix(md.Digest, "sha256:")
	if !ok || !sha256Re.MatchString(hexDigest) {
		return fail("the registry did not supply a sha256 digest for %s, so its signature cannot be checked", ref)
	}
	digest, _ := hex.DecodeString(hexDigest)
	expect := sigverify.Expect{OwnerLogin: owner}
	if o, r, ok := manifest.ParseRepository(md.Manifest.Metadata.Repository); ok && strings.EqualFold(o, owner) {
		expect.Repository = o + "/" + r
	}
	id, err := e.verifier()(sig, digest, expect)
	if err != nil {
		reason, stale := e.failureReason(err)
		if stale {
			return fail("%s: %s. %s", ref, reason, e.staleFix())
		}
		return fail("the signature attached to %s did not verify: %s", ref, reason)
	}
	if id.OwnerID <= 0 || id.RepositoryID <= 0 || id.Repository == "" {
		return fail("the signature attached to %s did not verify: its identity is incomplete", ref)
	}
	if res.OwnerID > 0 && res.OwnerID != id.OwnerID {
		return fail("the registry and the signature disagree about who owns %s/%s (the registry reports owner id %d, the signing certificate says %d)", owner, name, res.OwnerID, id.OwnerID)
	}
	detail := client.Sanitize(id.WorkflowRef)
	if sha := id.SourceSHA; sha != "" {
		if len(sha) > 7 {
			sha = sha[:7]
		}
		if detail != "" {
			detail += ", "
		}
		detail += "commit " + sha
	}
	if detail != "" {
		detail = ": " + detail
	}
	fmt.Fprintf(stderr, "signature: valid for the digest the registry reports (a GitHub Actions workflow in %s%s); the bundle itself was not downloaded, so capm did not check it against this signature\n",
		client.Sanitize(id.Repository), detail)
	switch p := rec.SignerPin; {
	case recorded && rec.OwnerID > 0 && rec.OwnerID != id.OwnerID:
		fmt.Fprintf(stderr, "signer pin: WARNING signed by owner id %d but you pinned %d (run/pull will refuse without --accept-new-owner)\n", id.OwnerID, rec.OwnerID)
	case !recorded || p == nil || p.RepositoryID == 0:
		fmt.Fprintln(stderr, "signer pin: not pinned yet; the signing repository is pinned the first time you pull or run a signed version")
	case p.RepositoryID == id.RepositoryID:
		fmt.Fprintf(stderr, "signer pin: signed from the repository you pinned (%s)\n", id.Repository)
	default:
		fmt.Fprintf(stderr, "signer pin: WARNING signed from %s (id %d) but you pinned %s (id %d); run/pull will refuse without --accept-new-signer\n",
			id.Repository, id.RepositoryID, client.Sanitize(p.Repository), p.RepositoryID)
	}
	return true
}

// signedWord is the outdated column text for the registry's claim.
func signedWord(signed bool) string {
	if signed {
		return "signed"
	}
	return "unsigned"
}
