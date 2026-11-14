package sigverify

import (
	"strings"
	"testing"

	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"google.golang.org/protobuf/proto"
)

// normalise clears the bytes of a parsed bundle that no check authenticates,
// so that two bundles equal after normalisation are the same bundle as far as
// verification can tell. Found by fuzzing (testdata/fuzz/FuzzVerify): the
// name on a Rekor checkpoint's signature line ("<em dash> <name> <base64>")
// is a label; the signature that follows it is what is verified, against the
// log key from the trusted root. Changing the name does not change who
// vouched for the entry.
func normalise(b *bundle.Bundle) *bundle.Bundle {
	out := &bundle.Bundle{Bundle: proto.Clone(b.Bundle).(*protobundle.Bundle)}
	for _, e := range out.GetVerificationMaterial().GetTlogEntries() {
		cp := e.GetInclusionProof().GetCheckpoint()
		if cp == nil {
			continue
		}
		lines := strings.Split(cp.Envelope, "\n")
		for i, l := range lines {
			if strings.HasPrefix(l, "— ") {
				if f := strings.Fields(l); len(f) > 0 {
					lines[i] = "— " + f[len(f)-1]
				}
			}
		}
		cp.Envelope = strings.Join(lines, "\n")
	}
	return out
}

// FuzzVerify checks, for arbitrary bytes standing in for a bundle, that
// verification (a) never panics and (b) never succeeds unless the input is
// the same bundle as the real fixture (parsed equal: JSON whitespace, key
// order and unknown fields do not change the bundle). It runs the same code
// as Verify but without the recover() in Verify, so a panic is a failure
// here instead of an error value.
//
// Run it explicitly; plain `go test` only replays the seed corpus:
//
//	go test -fuzz=FuzzVerify -fuzztime=30s ./internal/sigverify/
func FuzzVerify(f *testing.F) {
	good := readFixture(f, fixtureActions)
	f.Add(good)
	f.Add(readFixture(f, fixtureTwoSigs))
	f.Add(readFixture(f, fixturePublicKey))
	f.Add([]byte("{}"))
	f.Add([]byte(""))
	f.Add(mutate(f, good, func(m map[string]any) { flipBase64(f, m, "dsseEnvelope", "signatures", 0, "sig") }))
	f.Add(mutate(f, good, func(m map[string]any) {
		flipBase64(f, m, "verificationMaterial", "x509CertificateChain", "certificates", 0, "rawBytes")
	}))
	f.Add(mutate(f, good, func(m map[string]any) {
		flipBase64(f, m, "verificationMaterial", "tlogEntries", 0, "inclusionPromise", "signedEntryTimestamp")
	}))

	var ref bundle.Bundle
	if err := ref.UnmarshalJSON(good); err != nil {
		f.Fatal(err)
	}
	digest := fixtureDigest(f)
	v := realVerifier(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		_, err := v.verifyBytes(data, digest, actionsExpect())
		if err != nil {
			return
		}
		var got bundle.Bundle
		if perr := got.UnmarshalJSON(data); perr != nil || !proto.Equal(normalise(&got).Bundle, normalise(&ref).Bundle) {
			t.Fatalf("a bundle that differs from the fixture was accepted: %q", data)
		}
	})
}
