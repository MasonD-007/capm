// Baseline for size comparison: stdlib-only main that does comparable work
// (reads files, prints) so the linker keeps a similar stdlib footprint.
package main

import (
	"crypto/sha256"
	"fmt"
	"os"
)

func main() {
	b, _ := os.ReadFile(os.Args[1])
	s := sha256.Sum256(b)
	fmt.Printf("%x\n", s)
}
