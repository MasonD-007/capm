// fetchroot downloads a target (default trusted_root.json; also try
// signing_config.v0.2.json) through the real TUF client (initial root
// embedded in sigstore-go) into a throwaway cache dir and writes it to argv[1].
// It then prints the version/expiry of each cached TUF role. Read-only network.
//
//	fetchroot OUT [TARGET]
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sigstore/sigstore-go/pkg/tuf"
)

func main() {
	target := "trusted_root.json"
	if len(os.Args) > 2 {
		target = os.Args[2]
	}
	cache, _ := os.MkdirTemp("", "tufcache")
	defer os.RemoveAll(cache)
	opts := tuf.DefaultOptions().WithCachePath(cache)
	t0 := time.Now()
	c, err := tuf.New(opts)
	if err != nil {
		panic(err)
	}
	b, err := c.GetTarget(target)
	if err != nil {
		panic(err)
	}
	fmt.Fprintf(os.Stderr, "fetched %s: %d bytes in %v (cold cache)\n", target, len(b), time.Since(t0))
	if err := os.WriteFile(os.Args[1], b, 0o644); err != nil {
		panic(err)
	}
	filepath.Walk(cache, func(p string, i os.FileInfo, err error) error {
		if err != nil || i.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(cache, p)
		switch filepath.Base(p) {
		case "root.json", "timestamp.json", "snapshot.json", "targets.json":
			var m struct {
				Signed struct {
					Version int    `json:"version"`
					Expires string `json:"expires"`
				} `json:"signed"`
			}
			d, _ := os.ReadFile(p)
			json.Unmarshal(d, &m)
			fmt.Fprintf(os.Stderr, "  tuf %-40s version=%d expires=%s\n", rel, m.Signed.Version, m.Signed.Expires)
		default:
			fmt.Fprintf(os.Stderr, "  cache file %s (%d bytes)\n", rel, i.Size())
		}
		return nil
	})
}
