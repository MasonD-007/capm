//go:build ignore

// fetch-trusted-root downloads Sigstore's public-good trusted_root.json through
// the real TUF client (initial root embedded in sigstore-go, then the root
// chain and targets verified over the network) into a throwaway cache and
// writes it to argv[1]. If argv[2] names an existing trusted root it also
// prints which logs and authorities were added or removed relative to it.
// Read-only network access to the public Sigstore TUF repository; no
// credentials. Invoked by scripts/update-trusted-root.sh:
//
//	cd cli && go run ../scripts/fetch-trusted-root.go OUT [CURRENT]
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/sigstore/sigstore-go/pkg/tuf"
)

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, "usage: fetch-trusted-root OUT [CURRENT]")
		os.Exit(2)
	}
	cache, err := os.MkdirTemp("", "tufcache")
	if err != nil {
		fatal(err)
	}
	defer os.RemoveAll(cache)
	c, err := tuf.New(tuf.DefaultOptions().WithCachePath(cache))
	if err != nil {
		fatal(err)
	}
	b, err := c.GetTarget("trusted_root.json")
	if err != nil {
		fatal(err)
	}
	if err := os.WriteFile(os.Args[1], b, 0o644); err != nil {
		fatal(err)
	}
	fmt.Fprintf(os.Stderr, "fetched trusted_root.json (%d bytes) via %s\n", len(b), tuf.DefaultMirror)
	if len(os.Args) == 3 {
		old, err := os.ReadFile(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, "no current file to compare:", err)
			return
		}
		diff(summary(old), summary(b))
	}
}

type validity struct {
	Start string `json:"start"`
	End   string `json:"end"`
}

type entry struct {
	BaseURL   string `json:"baseUrl"`
	URI       string `json:"uri"`
	PublicKey struct {
		ValidFor validity `json:"validFor"`
	} `json:"publicKey"`
	ValidFor validity `json:"validFor"`
}

// summary lists one line per log or authority: kind, URL, validity window.
func summary(raw []byte) map[string]bool {
	var r map[string]json.RawMessage
	if err := json.Unmarshal(raw, &r); err != nil {
		fatal(err)
	}
	out := map[string]bool{}
	for _, kind := range []string{"tlogs", "certificateAuthorities", "ctlogs", "timestampAuthorities"} {
		var es []entry
		if err := json.Unmarshal(r[kind], &es); err != nil {
			fatal(err)
		}
		for _, e := range es {
			u, v := e.BaseURL, e.PublicKey.ValidFor
			if u == "" {
				u, v = e.URI, e.ValidFor
			}
			out[fmt.Sprintf("%-22s %-50s %s .. %s", kind, u, norm(v.Start), norm(v.End))] = true
		}
	}
	return out
}

// norm renders a timestamp the same way whatever fractional-second spelling
// the file used; an empty time means "open ended".
func norm(s string) string {
	if s == "" {
		return "open"
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return s
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

func diff(old, cur map[string]bool) {
	var lines []string
	for k := range old {
		if !cur[k] {
			lines = append(lines, "removed/changed: "+k)
		}
	}
	for k := range cur {
		if !old[k] {
			lines = append(lines, "added/changed:   "+k)
		}
	}
	sort.Strings(lines)
	if len(lines) == 0 {
		fmt.Println("no change in logs or authorities")
		return
	}
	for _, l := range lines {
		fmt.Println(l)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "fetch-trusted-root:", err)
	os.Exit(1)
}
