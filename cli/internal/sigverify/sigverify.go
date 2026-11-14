// Package sigverify checks that a downloaded bundle tarball was signed, with a
// Sigstore keyless signature, by a specific GitHub Actions workflow.
//
// It is bytes in, typed result out: no files, no environment, no network, no
// global state mutated, safe for concurrent use. Trust comes only from the
// Sigstore public-good trusted root embedded in this binary (trusted_root.json);
// there is no TUF client call and no online refresh. See README.md for the
// guarantees, the policy and what a caller must still do.
package sigverify

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tlog"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
)

// MaxBundleSize is the largest bundle Verify will parse. Real bundles are
// 4-10 KB.
const MaxBundleSize = 64 << 10

// Identity is what a verified signature proves about its signer. Every string
// field has been checked against the shape of a legitimate GitHub value (see
// README.md); informational fields that fail their shape check are left empty
// rather than surfaced.
type Identity struct {
	Issuer       string    // always ActionsIssuer for an accepted signature
	OwnerLogin   string    // from the certificate's source-repository-owner URI, in GitHub's case
	OwnerID      int64     // certificate's numeric repository owner id (always > 0)
	Repository   string    // "owner/repo" from the certificate's source repository URI
	RepositoryID int64     // certificate's numeric repository id (always > 0)
	WorkflowRef  string    // the workflow that ran: build signer URI, else the SAN (job_workflow_ref); may name a reusable workflow in another repository
	SourceRef    string    // git ref the workflow ran on, sanitised
	SourceSHA    string    // commit the workflow ran on; empty unless 40 or 64 lower-case hex
	RunURL       string    // the Actions run; empty unless it has the shape of one
	SignedAt     time.Time // integrated time from the transparency log
}

// Expect is the policy a signature must satisfy. Zero-valued optional fields
// are not checked.
type Expect struct {
	OwnerLogin   string // required: the bundle's owner as the user typed it; compared case-insensitively
	OwnerID      int64  // optional: pinned owner id from an earlier run
	RepositoryID int64  // optional: pinned repository id from an earlier run
	Repository   string // optional: "owner/repo" the manifest names; compared case-insensitively
}

//go:embed trusted_root.json
var embeddedRootJSON []byte

// embeddedRoot parses the embedded root once. The parsed value is read-only.
var embeddedRoot = sync.OnceValues(func() (*root.TrustedRoot, error) {
	return root.NewTrustedRootFromJSON(embeddedRootJSON)
})

// Verify checks that sigBundle is a valid Sigstore bundle over the artifact
// whose SHA-256 is digest (raw 32 bytes), signed by a GitHub Actions workflow
// satisfying want, using only the trust root embedded in this binary.
//
// On success the returned Identity is what the caller should pin. Errors
// satisfy errors.Is against ErrInvalidInput, ErrMalformed, ErrUntrusted,
// ErrIdentity (see *IdentityError) or ErrStaleTrustRoot (see
// *StaleTrustRootError). Verify never panics; an unexpected panic inside a
// dependency is reported as ErrMalformed.
func Verify(sigBundle []byte, digest []byte, want Expect) (id Identity, err error) {
	tr, rerr := embeddedRoot()
	if rerr != nil {
		return Identity{}, newErr(ErrUntrusted, "embedded trust root is unusable", rerr)
	}
	v := &verifier{tr: tr, now: time.Now, profile: productionProfile, policy: checkIdentity}
	defer func() {
		if r := recover(); r != nil {
			id, err = Identity{}, newErr(ErrMalformed, "internal error while verifying", fmt.Errorf("%v", r))
		}
	}()
	return v.verifyBytes(sigBundle, digest, want)
}

// profile is the shape of signature a verifier accepts. Production accepts
// exactly one; tests use others to exercise real third-party fixtures.
type profile struct {
	alg        string   // artifact digest algorithm
	digestLen  int      // its length in bytes
	versions   []string // accepted bundle media-type versions
	allowDSSE  bool     // accept a DSSE envelope (in-toto) instead of a message signature
	requireSCT bool     // require a valid embedded SCT
}

var productionProfile = profile{alg: "sha256", digestLen: 32, versions: []string{"v0.3"}, requireSCT: true}

type verifier struct {
	tr      root.TrustedMaterial
	now     func() time.Time
	profile profile
	policy  func(certificate.Summary, Expect) (Identity, error)
}

func (v *verifier) verifyBytes(raw, digest []byte, want Expect) (Identity, error) {
	if err := validateExpect(want); err != nil {
		return Identity{}, err
	}
	if len(digest) != v.profile.digestLen {
		return Identity{}, newErr(ErrInvalidInput, fmt.Sprintf("digest must be exactly %d bytes", v.profile.digestLen), nil)
	}
	if len(raw) == 0 {
		return Identity{}, newErr(ErrMalformed, "empty bundle", nil)
	}
	if len(raw) > MaxBundleSize {
		return Identity{}, newErr(ErrMalformed, fmt.Sprintf("bundle larger than %d bytes", MaxBundleSize), nil)
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		return Identity{}, newErr(ErrMalformed, "cannot parse bundle", err)
	}
	return v.verifyEntity(&b, digest, want)
}

// verifyEntity is everything after parsing; tests call it directly with
// sigstore-go's in-memory fake Sigstore.
func (v *verifier) verifyEntity(e sgverify.SignedEntity, digest []byte, want Expect) (Identity, error) {
	leaf, entry, err := v.checkShape(e)
	if err != nil {
		return Identity{}, err
	}
	signedAt := entry.IntegratedTime()
	now := v.now()
	if signedAt.After(now.Add(maxFutureSkew)) {
		return Identity{}, newErr(ErrUntrusted, "the log dates this signature in the future; check the system clock", nil)
	}
	if err := v.checkCoverage(entry, leaf, now); err != nil {
		return Identity{}, err
	}

	opts := []sgverify.VerifierOption{
		sgverify.WithTransparencyLog(1),      // Rekor inclusion proof / signed entry timestamp
		sgverify.WithIntegratedTimestamps(1), // the log's time validates the 10-minute certificate
	}
	if v.profile.requireSCT {
		opts = append(opts, sgverify.WithSignedCertificateTimestamps(1))
	}
	sv, err := sgverify.NewVerifier(v.tr, opts...)
	if err != nil {
		return Identity{}, newErr(ErrUntrusted, "cannot configure verifier", err)
	}
	// The identity policy is applied below on the verified certificate, not by
	// the library, so that owner and repository come from the extensions and
	// every value is shape-checked before use.
	pol := sgverify.NewPolicy(sgverify.WithArtifactDigest(v.profile.alg, digest), sgverify.WithoutIdentitiesUnsafe())
	res, err := sv.Verify(e, pol)
	if err != nil {
		return Identity{}, newErr(ErrUntrusted, "verification failed", err)
	}
	if res.Signature == nil || res.Signature.Certificate == nil {
		return Identity{}, newErr(ErrUntrusted, "no certificate in verification result", nil)
	}
	id, err := v.policy(*res.Signature.Certificate, want)
	if err != nil {
		return Identity{}, err
	}
	id.SignedAt = signedAt.UTC()
	return id, nil
}

// maxFutureSkew is how far ahead of the local clock a log timestamp may be.
const maxFutureSkew = 10 * time.Minute

// checkShape enforces the one accepted bundle shape and returns the leaf
// certificate and the single transparency-log entry.
func (v *verifier) checkShape(e sgverify.SignedEntity) (*x509.Certificate, *tlog.Entry, error) {
	ver, err := e.Version()
	if err != nil {
		return nil, nil, newErr(ErrMalformed, "no bundle version", err)
	}
	okVer := false
	for _, w := range v.profile.versions {
		okVer = okVer || ver == w
	}
	if !okVer {
		return nil, nil, newErr(ErrMalformed, "unsupported bundle media type version", nil)
	}
	sc, err := e.SignatureContent()
	if err != nil || sc == nil {
		return nil, nil, newErr(ErrMalformed, "no signature content", err)
	}
	switch {
	case sc.MessageSignatureContent() != nil:
	case v.profile.allowDSSE && sc.EnvelopeContent() != nil:
		if len(sc.EnvelopeContent().RawEnvelope().Signatures) != 1 {
			return nil, nil, newErr(ErrMalformed, "exactly one signature is required", nil)
		}
	default:
		return nil, nil, newErr(ErrMalformed, "bundle is not a message signature", nil)
	}
	vc, err := e.VerificationContent()
	if err != nil || vc == nil {
		return nil, nil, newErr(ErrMalformed, "no verification material", err)
	}
	leaf := vc.Certificate()
	if leaf == nil || vc.PublicKey() != nil {
		return nil, nil, newErr(ErrMalformed, "a Fulcio certificate is required; public-key signatures are not accepted", nil)
	}
	entries, err := e.TlogEntries()
	if err != nil {
		return nil, nil, newErr(ErrMalformed, "unreadable transparency log entries", err)
	}
	if len(entries) != 1 {
		return nil, nil, newErr(ErrMalformed, "exactly one transparency log entry is required", nil)
	}
	return leaf, entries[0], nil
}

func validAt(start, end, t time.Time) bool {
	return (start.IsZero() || !t.Before(start)) && (end.IsZero() || !t.After(end))
}

// checkCoverage decides whether the embedded trust root can speak to this
// signature at all, before any cryptography runs. It returns a
// *StaleTrustRootError when:
//
//   - nothing in the root is valid today: no Rekor log or no Fulcio CA whose
//     validity window contains the current time (the root has aged out); or
//   - the log entry names a log key the root has never heard of (Sigstore added
//     or rotated a log after this build); or
//   - the leaf certificate was issued by a key that none of the root's Fulcio
//     CAs (roots and intermediates) matches (a CA rotation after this build).
//
// Anything else that goes wrong (a window that excludes the signature time, a
// bad proof) is not staleness and is left to the verifier, which reports
// ErrUntrusted. The first and second cases cannot be told apart from a forged
// bundle offline; both are refused.
func (v *verifier) checkCoverage(entry *tlog.Entry, leaf *x509.Certificate, now time.Time) error {
	stale := func(reason string) error { return &StaleTrustRootError{Reason: reason} }

	logs := v.tr.RekorLogs()
	currentLog := false
	for _, l := range logs {
		currentLog = currentLog || validAt(l.ValidityPeriodStart, l.ValidityPeriodEnd, now)
	}
	var cas []*root.FulcioCertificateAuthority
	currentCA := false
	for _, c := range v.tr.FulcioCertificateAuthorities() {
		if f, ok := c.(*root.FulcioCertificateAuthority); ok {
			cas = append(cas, f)
			currentCA = currentCA || validAt(f.ValidityPeriodStart, f.ValidityPeriodEnd, now)
		}
	}
	if !currentLog || !currentCA {
		return stale("no currently valid transparency log or certificate authority in the embedded trust root")
	}
	if _, ok := logs[hex.EncodeToString([]byte(entry.LogKeyID()))]; !ok {
		return stale("the signature was logged in a transparency log this build does not know")
	}
	for _, f := range cas {
		for _, c := range append([]*x509.Certificate{f.Root}, f.Intermediates...) {
			if c == nil {
				continue
			}
			if bytes.Equal(leaf.RawIssuer, c.RawSubject) &&
				(len(leaf.AuthorityKeyId) == 0 || bytes.Equal(leaf.AuthorityKeyId, c.SubjectKeyId)) {
				return nil
			}
		}
	}
	return stale("the signing certificate was issued by a certificate authority this build does not know")
}
