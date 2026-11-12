package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/MasonD-007/capm/cli/internal/client"
)

const (
	listPageSize = 200
	listMax      = 2000 // hard cap on bundles printed by one command
	listDescMax  = 80   // runes of description shown
)

// sortFlagValues are the values of --sort.
const sortFlagValues = "name|recent|downloads"

// splitSort pulls one --sort VALUE / --sort=VALUE out of args (before or
// after the positional arguments) and returns the rest. ok is false for a
// missing, unknown or repeated value. "name" is the registry's default order,
// so it (like no flag) returns sortBy "".
func splitSort(args []string) (rest []string, sortBy string, ok bool) {
	given := false
	for i := 0; i < len(args); i++ {
		v, isSort := "", false
		switch a := args[i]; {
		case a == "--sort":
			if i+1 >= len(args) {
				return nil, "", false
			}
			i++
			v, isSort = args[i], true
		case strings.HasPrefix(a, "--sort="):
			v, isSort = strings.TrimPrefix(a, "--sort="), true
		}
		if !isSort {
			rest = append(rest, args[i])
			continue
		}
		if given {
			return nil, "", false
		}
		given = true
		switch v {
		case "name":
		case "recent", "downloads":
			sortBy = v
		default:
			return nil, "", false
		}
	}
	return rest, sortBy, true
}

// search prints the bundles whose owner, name or description contains args[0].
func search(args []string, stdout, stderr io.Writer, e env) int {
	rest, sortBy, ok := splitSort(args)
	if !ok || len(rest) != 1 {
		fmt.Fprintln(stderr, "usage: capm search <text> [--sort "+sortFlagValues+"]")
		return 2
	}
	return listBundles("search", rest[0], "", sortBy, stdout, stderr, e)
}

// list prints every bundle, or only args[0]'s when an owner is given.
func list(args []string, stdout, stderr io.Writer, e env) int {
	rest, sortBy, ok := splitSort(args)
	if !ok || len(rest) > 1 {
		fmt.Fprintln(stderr, "usage: capm list [owner] [--sort "+sortFlagValues+"]")
		return 2
	}
	owner := ""
	if len(rest) == 1 {
		owner = rest[0]
	}
	return listBundles("list", "", owner, sortBy, stdout, stderr, e)
}

// listBundles pages through the registry (no login needed) and prints one
// aligned line per bundle. Every field comes from the registry and is
// sanitised before it reaches the terminal.
//
// sortBy is "", "recent" or "downloads". With the latter two the registry
// orders the list and each row gets that value as a column; a registry that
// ignores sort (it sends no downloads30d) gets one stderr note and the plain
// table.
func listBundles(cmd, q, owner, sortBy string, stdout, stderr io.Writer, e env) int {
	c := client.New(e.registry, "")
	var all []client.BundleInfo
	truncated := false
	for len(all) < listMax {
		page, err := c.ListBundlesSorted(q, owner, sortBy, listPageSize, len(all))
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
	if sortBy != "" && all[0].Downloads30d == nil {
		fmt.Fprintf(stderr, "capm %s: this registry does not support sorting; showing the default order\n", cmd)
		sortBy = ""
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
		fmt.Fprintf(tw, "%s/%s\t%s\t", client.Sanitize(b.Owner), client.Sanitize(b.Name), latest)
		if sortBy != "" {
			fmt.Fprintf(tw, "%s\t", sortCell(sortBy, b))
		}
		if marked {
			fmt.Fprintf(tw, "%s\t", riskMarker(b.Risk))
		}
		fmt.Fprintf(tw, "%s\n", shortDesc(b.Description))
	}
	tw.Flush()
	if truncated {
		fmt.Fprintf(stderr, "output truncated at %d bundles; narrow it with `capm search`\n", listMax)
	}
	return 0
}

// sortCell is the extra column of a sorted listing: the raw 30-day download
// count as a plain integer, or the last-published date as YYYY-MM-DD ("-" when
// the registry sent none or something that is not a date). Both come from the
// registry, so neither is echoed as received.
func sortCell(sortBy string, b client.BundleInfo) string {
	if sortBy == "downloads" {
		if b.Downloads30d == nil || *b.Downloads30d < 0 {
			return "-"
		}
		return strconv.FormatInt(*b.Downloads30d, 10)
	}
	t, err := time.Parse(time.RFC3339, b.UpdatedAt)
	if err != nil {
		return "-"
	}
	return t.UTC().Format("2006-01-02")
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
