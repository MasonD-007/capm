package main

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/MasonD-007/capm/cli/internal/client"
)

// completeTimeout is the hard total budget for the registry request a
// completion may make.
const completeTimeout = time.Second

// completeLimit is how many search results are asked for.
const completeLimit = 20

// completePrefixRe is what a bundle reference being typed can contain:
// owner/name[@version] and nothing a shell would treat specially.
var completePrefixRe = regexp.MustCompile(`^[A-Za-z0-9._/@+-]{0,200}$`)

// completeCmd implements the hidden `capm __complete <what> <args>...` that
// the generated shell scripts call for dynamic words. Today the only <what>
// is `bundles <prefix>`.
//
// It is built to be run on every TAB press, so: it prints only to stdout
// (never stderr, whatever goes wrong), always exits 0, writes no file (the
// known.json read is through a store whose warnings are discarded, and
// nothing is recorded), sends no credentials (the client has no token), and
// is skipped by the once-a-day update notice (noticeSkipCommands). Anything it
// does not understand prints nothing.
func completeCmd(args []string, stdout io.Writer, e env) int {
	if len(args) == 2 && args[0] == "bundles" {
		for _, s := range completeBundles(args[1], e) {
			fmt.Fprintln(stdout, s)
		}
	}
	return 0
}

// refSafe reports whether s is a well-formed owner/name[@version]
// (version optional). Everything printed by __complete passes this, so a
// hostile registry cannot put spaces, quotes, $(), backticks, ; | & < >,
// globs, newlines or escape sequences into the list: such candidates are
// dropped rather than cleaned up, because a cleaned-up name would be a
// different bundle.
func refSafe(s string) bool {
	if !completePrefixRe.MatchString(s) || s == "" {
		return false
	}
	_, _, _, err := parseRef(s)
	return err == nil
}

func completeBundles(prefix string, e env) []string {
	if !completePrefixRe.MatchString(prefix) || strings.Count(prefix, "@") > 1 {
		return nil
	}
	ref, _, hasVer := strings.Cut(prefix, "@")
	var out []string
	add := func(s string) {
		if strings.HasPrefix(s, prefix) && refSafe(s) && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	// 1. What this machine has already pulled or run for this registry:
	// instant and offline.
	known := newKnownStore(e, io.Discard)
	var recorded []knownEntry
	if known.dir != "" {
		recorded = known.all()
	}
	for _, en := range recorded {
		if en.Registry != e.registry {
			continue
		}
		if !hasVer {
			add(en.Key)
		} else if en.Key == ref && en.Record.LastRun != nil {
			add(en.Key + "@" + en.Record.LastRun.Version)
		}
	}
	// 2. The registry, with one hard budget for the whole request.
	c := client.New(e.registry, "")
	c.SetTimeout(completeTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), completeTimeout)
	defer cancel()
	done := make(chan []string, 1)
	go func() { done <- fromRegistry(c, prefix, ref, hasVer) }()
	select {
	case more := <-done:
		for _, s := range more {
			add(s)
		}
	case <-ctx.Done():
	}
	return out
}

// fromRegistry returns candidate refs from the registry (unfiltered; the
// caller applies the prefix and the safety check). Any error yields none.
func fromRegistry(c *client.Client, prefix, ref string, hasVer bool) []string {
	var out []string
	if hasVer {
		owner, name, ok := strings.Cut(ref, "/")
		if !ok || !refSafe(ref) {
			return nil
		}
		vs, err := c.Versions(owner, name)
		if err != nil {
			return nil
		}
		for _, v := range vs {
			if !v.Removed {
				out = append(out, ref+"@"+v.Version)
			}
		}
		return out
	}
	// "owner/na" narrows by owner (the search text would not match the
	// slash); anything else is the search text.
	q, owner := prefix, ""
	if o, _, ok := strings.Cut(prefix, "/"); ok {
		q, owner = "", o
	}
	bs, err := c.ListBundles(q, owner, completeLimit, 0)
	if err != nil {
		return nil
	}
	for _, b := range bs {
		out = append(out, b.Owner+"/"+b.Name)
	}
	return out
}
