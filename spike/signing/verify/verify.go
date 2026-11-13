// Package verify is the throwaway verification prototype: check a Sigstore
// bundle against an artifact digest and an identity policy, fully offline,
// from a trusted_root.json supplied by the caller.
package verify

import (
	"fmt"
	"regexp"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	sgverify "github.com/sigstore/sigstore-go/pkg/verify"
)

// Policy is what capm would derive from the bundle owner.
type Policy struct {
	Issuer  string // exact OIDC issuer, e.g. https://token.actions.githubusercontent.com
	SANRe   string // regexp for the certificate SAN (anchored by the caller)
	OwnerID string // optional: numeric repository-owner id (Fulcio OID 1.3.6.1.4.1.57264.1.17)
}

// ActionsPolicy builds the CI policy for a bundle owned by login/ownerID.
func ActionsPolicy(login, ownerID string) Policy {
	return Policy{
		Issuer:  "https://token.actions.githubusercontent.com",
		SANRe:   `^https://github\.com/` + regexp.QuoteMeta(login) + `/[^/]+/\.github/workflows/[^@]+@.+$`,
		OwnerID: ownerID,
	}
}

// Result is what a caller would show in `inspect`.
type Result struct {
	SAN, Issuer, Repo, OwnerID, WorkflowRef string
}

// Verify checks bundleJSON against sha256 digest (raw 32 bytes) and policy,
// using trustedRootJSON. No network access happens here.
func Verify(bundleJSON, trustedRootJSON []byte, alg string, digest []byte, p Policy) (*Result, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}
	tr, err := root.NewTrustedRootFromJSON(trustedRootJSON)
	if err != nil {
		return nil, fmt.Errorf("parse trusted root: %w", err)
	}
	return VerifyEntity(&b, tr, true, alg, digest, p)
}

// VerifyEntity is Verify for an already-parsed entity and trusted material
// (used by tests with sigstore-go's in-memory VirtualSigstore, whose certs
// carry no SCT, hence requireSCT).
func VerifyEntity(entity sgverify.SignedEntity, tr root.TrustedMaterial, requireSCT bool, alg string, digest []byte, p Policy) (*Result, error) {
	// Rekor inclusion proof/promise (offline) + signed integrated time from
	// the log as the time source for the short-lived Fulcio certificate.
	opts := []sgverify.VerifierOption{
		sgverify.WithTransparencyLog(1),
		sgverify.WithIntegratedTimestamps(1),
	}
	if requireSCT {
		opts = append(opts, sgverify.WithSignedCertificateTimestamps(1)) // Fulcio's embedded CT SCT
	}
	v, err := sgverify.NewVerifier(tr, opts...)
	if err != nil {
		return nil, err
	}
	san, err := sgverify.NewSANMatcher("", p.SANRe)
	if err != nil {
		return nil, err
	}
	iss, err := sgverify.NewIssuerMatcher(p.Issuer, "")
	if err != nil {
		return nil, err
	}
	ext := certificate.Extensions{SourceRepositoryOwnerIdentifier: p.OwnerID}
	id, err := sgverify.NewCertificateIdentity(san, iss, ext)
	if err != nil {
		return nil, err
	}
	pol := sgverify.NewPolicy(
		sgverify.WithArtifactDigest(alg, digest),
		sgverify.WithCertificateIdentity(id),
	)
	res, err := v.Verify(entity, pol)
	if err != nil {
		return nil, err
	}
	out := &Result{}
	if c := res.Signature.Certificate; c != nil {
		out.SAN, out.Issuer = c.SubjectAlternativeName, c.Extensions.Issuer
		out.Repo, out.OwnerID = c.SourceRepositoryURI, c.SourceRepositoryOwnerIdentifier
		out.WorkflowRef = c.BuildSignerURI
	}
	return out, nil
}
