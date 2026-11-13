// Baseline 2: pulls in the stdlib packages the real CLI already links
// (net/http, crypto/tls, encoding/json, regexp, os/exec, ...) so that the
// delta against the verifier build is not inflated by shared stdlib.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"text/tabwriter"
	"archive/tar"
	"compress/gzip"
)

func main() {
	b, _ := os.ReadFile(os.Args[1])
	s := sha256.Sum256(b)
	_ = tls.Config{}
	_ = http.DefaultClient
	_ = tabwriter.NewWriter
	_ = tar.NewReader
	_ = gzip.NewReader
	_, _ = json.Marshal(s)
	_ = exec.Command
	fmt.Println(regexp.MustCompile("a").MatchString(os.Args[2]))
}
