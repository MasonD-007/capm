package verify

import (
	"crypto/sha256"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/testing/ca"
)

// Offline round trip against sigstore-go's in-memory fake Fulcio+Rekor:
// no network, no real identity. The fake CA only issues email-SAN certs with
// the legacy issuer OID, so the Actions owner-id policy cannot be exercised
// here (see findings); that is covered by the real fixture bundles instead.
func TestVirtualSigstoreRoundTrip(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	artifact := []byte("pretend tarball bytes")
	sum := sha256.Sum256(artifact)
	ent, err := vs.Sign("dev@example.com", "https://github.com/login/oauth", artifact)
	if err != nil {
		t.Fatal(err)
	}
	ok := Policy{Issuer: "https://github.com/login/oauth", SANRe: `^dev@example\.com$`}
	if _, err := VerifyEntity(ent, vs, false, "sha256", sum[:], ok); err != nil {
		t.Fatalf("valid: %v", err)
	}
	bad := sum
	bad[0] ^= 1
	if _, err := VerifyEntity(ent, vs, false, "sha256", bad[:], ok); err == nil {
		t.Fatal("wrong digest accepted")
	}
	wrong := ok
	wrong.SANRe = `^other@example\.com$`
	if _, err := VerifyEntity(ent, vs, false, "sha256", sum[:], wrong); err == nil {
		t.Fatal("wrong SAN accepted")
	}
	wrong = ok
	wrong.Issuer = "https://accounts.google.com"
	if _, err := VerifyEntity(ent, vs, false, "sha256", sum[:], wrong); err == nil {
		t.Fatal("wrong issuer accepted")
	}
	// An attacker's own fake CA is not in the trusted material.
	evil, _ := ca.NewVirtualSigstore()
	ent2, _ := evil.Sign("dev@example.com", "https://github.com/login/oauth", artifact)
	if _, err := VerifyEntity(ent2, vs, false, "sha256", sum[:], ok); err == nil {
		t.Fatal("entity from untrusted CA accepted")
	}
}
