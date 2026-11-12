package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/MasonD-007/capm/cli/internal/client"
)

const (
	listPageSize = 200
	listMax      = 2000 // hard cap on bundles printed by one command
	listDescMax  = 80   // runes of description shown
)

// search prints the bundles whose owner, name or description contains args[0].
func search(args []string, stdout, stderr io.Writer, e env) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: capm search <text>")
		return 2
	}
	return listBundles("search", args[0], "", stdout, stderr, e)
}

// list prints every bundle, or only args[0]'s when an owner is given.
func list(args []string, stdout, stderr io.Writer, e env) int {
	if len(args) > 1 {
		fmt.Fprintln(stderr, "usage: capm list [owner]")
		return 2
	}
	owner := ""
	if len(args) == 1 {
		owner = args[0]
	}
	return listBundles("list", "", owner, stdout, stderr, e)
}

// listBundles pages through the registry (no login needed) and prints one
// aligned line per bundle. Every field comes from the registry and is
// sanitised before it reaches the terminal.
func listBundles(cmd, q, owner string, stdout, stderr io.Writer, e env) int {
	c := client.New(e.registry, "")
	var all []client.BundleInfo
	truncated := false
	for len(all) < listMax {
		page, err := c.ListBundles(q, owner, listPageSize, len(all))
		if err != nil {
			fmt.Fprintf(stderr, "capm %s: %v\n", cmd, err)
			return 1
		}
		all = append(all, page...)
		if len(page) < listPageSize {
			break
		}
		if len(all) >= listMax {
			truncated = true
		}
	}
	if len(all) == 0 {
		fmt.Fprintln(stderr, "no bundles found")
		return 0
	}
	// The marker column is only present when some row has a marker, so a
	// registry that sends no `risk` (or flags nothing) prints the table as it
	// always was.
	marked := false
	for _, b := range all {
		marked = marked || riskMarker(b.Risk) != ""
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	for _, b := range all {
		latest := client.Sanitize(b.Latest)
		if latest == "" {
			latest = "-" // every version is yanked or removed
		}
		if marked {
			fmt.Fprintf(tw, "%s/%s\t%s\t%s\t%s\n", client.Sanitize(b.Owner), client.Sanitize(b.Name), latest, riskMarker(b.Risk), shortDesc(b.Description))
			continue
		}
		fmt.Fprintf(tw, "%s/%s\t%s\t%s\n", client.Sanitize(b.Owner), client.Sanitize(b.Name), latest, shortDesc(b.Description))
	}
	tw.Flush()
	if truncated {
		fmt.Fprintf(stderr, "output truncated at %d bundles; narrow it with `capm search`\n", listMax)
	}
	return 0
}

// shortDesc is the sanitised first line of a description, at most
// listDescMax runes with a trailing … when cut.
func shortDesc(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	s, _, _ = strings.Cut(s, "\r")
	r := []rune(client.Sanitize(s))
	if len(r) > listDescMax {
		return string(r[:listDescMax-1]) + "…"
	}
	return string(r)
}

// riskMarker maps the registry's claimed highest risk severity to a compact
// marker: "!!" high, "!" caution, "" for anything else (including an older
// server that sends nothing). It is the registry's claim, not a verdict; a
// blank is not an endorsement. Unknown strings are never echoed.
func riskMarker(risk string) string {
	switch risk {
	case "high":
		return "!!"
	case "caution":
		return "!"
	}
	return ""
}
