// Same as emptymain plus the verifier code path and an embedded trusted root.
// This is what capm would link in: verify.Verify + embedded trusted_root.json.
package main

import (
	_ "embed"
	"crypto/sha256"
	"fmt"
	"os"

	"spike/signing/verify"
)

//go:embed trusted_root.json
var trustedRoot []byte

func main() {
	b, _ := os.ReadFile(os.Args[1])
	s := sha256.Sum256(b)
	bj, _ := os.ReadFile(os.Args[2])
	res, err := verify.Verify(bj, trustedRoot, "sha256", s[:], verify.ActionsPolicy(os.Args[3], ""))
	fmt.Println(res, err)
}
