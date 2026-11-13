// dumpcert prints the Fulcio certificate summary (SAN, issuer, OID
// extensions) and the Rekor entry kinds of a bundle, without verifying it.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/sigstore/sigstore-go/pkg/bundle"
)

func main() {
	b, err := bundle.LoadJSONFromPath(os.Args[1])
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	vc, err := b.VerificationContent()
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	fmt.Println("mediaType:", b.MediaType)
	if c := vc.Certificate(); c != nil {
		fmt.Println("notBefore:", c.NotBefore, "notAfter:", c.NotAfter)
	}
	if s, err := b.SignatureContent(); err == nil {
		if m := s.MessageSignatureContent(); m != nil {
			fmt.Printf("messageSignature digestAlg=%s digest=%x\n", m.DigestAlgorithm(), m.Digest())
		}
		if e := s.EnvelopeContent(); e != nil {
			st, _ := e.RawEnvelope(), 0
			_ = st
			fmt.Println("dsse envelope present")
		}
	}
	ents, _ := b.TlogEntries()
	for _, e := range ents {
		fmt.Printf("tlog: logIndex=%d integratedTime=%v hasProof=%v hasPromise=%v\n",
			e.LogIndex(), e.IntegratedTime(), e.HasInclusionProof(), e.HasInclusionPromise())
	}
	if c := vc.Certificate(); c != nil {
		// summary via the library's own parser
		sum, err := certSummary(c)
		if err != nil {
			fmt.Println("summary error:", err)
			return
		}
		j, _ := json.MarshalIndent(sum, "", "  ")
		fmt.Println(string(j))
	}
}
