// spikeverify: offline verification demo.
//
//	spikeverify -bundle b.json -root trusted_root.json -digest <hex|file> \
//	    -owner sigstore [-owner-id N] [-issuer URL] [-san-re REGEXP]
package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"spike/signing/verify"
)

//go:embed trusted_root.json
var embedded embed.FS

func main() {
	bundlePath := flag.String("bundle", "", "sigstore bundle json")
	rootPath := flag.String("root", "", "trusted_root.json (default: the embedded copy)")
	digestArg := flag.String("digest", "", "sha256 hex, or path to the artifact file")
	owner := flag.String("owner", "", "expected repository owner login")
	ownerID := flag.String("owner-id", "", "expected numeric owner id (empty = not checked)")
	issuer := flag.String("issuer", "", "override issuer")
	sanRe := flag.String("san-re", "", "override SAN regexp")
	alg := flag.String("alg", "sha256", "digest algorithm of -digest (sha256|sha512)")
	flag.Parse()

	t0 := time.Now()
	bj, err := os.ReadFile(*bundlePath)
	must(err)
	var rj []byte
	if *rootPath != "" {
		rj, err = os.ReadFile(*rootPath)
	} else {
		rj, err = embedded.ReadFile("trusted_root.json")
	}
	must(err)
	var dg []byte
	if len(*digestArg) == 64 || len(*digestArg) == 128 {
		dg, err = hex.DecodeString(*digestArg)
		must(err)
	} else {
		f, err := os.Open(*digestArg)
		must(err)
		h := sha256.New()
		_, err = io.Copy(h, f)
		must(err)
		dg = h.Sum(nil)
	}
	p := verify.ActionsPolicy(*owner, *ownerID)
	if *issuer != "" {
		p.Issuer = *issuer
	}
	if *sanRe != "" {
		p.SANRe = *sanRe
	}
	res, err := verify.Verify(bj, rj, *alg, dg, p)
	if err != nil {
		fmt.Printf("FAIL: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK  san=%s\n    issuer=%s\n    repo=%s\n    ownerId=%s\n    signer=%s\n    verify-time(excluding artifact hashing)~%v\n",
		res.SAN, res.Issuer, res.Repo, res.OwnerID, res.WorkflowRef, time.Since(t0))
}

func must(err error) {
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(2)
	}
}
