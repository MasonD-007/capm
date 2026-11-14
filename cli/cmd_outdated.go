package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/MasonD-007/capm/cli/internal/client"
	"github.com/MasonD-007/capm/manifest"
)

type outdatedRow struct {
	key, ran, latest, changes string
	signed                    string // the registry's claim for latest: "signed", "unsigned", or "" when it did not say
}

// outdated implements `capm outdated`: for every bundle recorded in known.json
// as run against this registry, ask for the latest installable version and say
// what it changes. It only reads: nothing is downloaded, run or recorded.
func outdated(args []string, stdout, stderr io.Writer, e env) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: capm outdated")
		return 2
	}
	ks := newKnownStore(e, stderr)
	var entries []knownEntry
	for _, en := range ks.all() {
		if en.Registry == e.registry && en.Record.LastRun != nil && en.Record.LastRun.Version != "" {
			entries = append(entries, en)
		}
	}
	if len(entries) == 0 {
		fmt.Fprintln(stdout, "nothing recorded yet; capm outdated lists bundles you have run")
		return 0
	}

	c := client.New(e.registry, "")
	var rows []outdatedRow
	current, answered := 0, 0
	for _, en := range entries {
		row, state := checkOutdated(c, en)
		switch state {
		case stateCurrent:
			current++
			answered++
		case stateDiffers, stateRegistryAnswer:
			answered++
			rows = append(rows, row)
		default:
			rows = append(rows, row)
		}
	}

	if len(rows) > 0 {
		// The signed column appears only when the registry said something
		// about signatures; an older registry's output is unchanged.
		showSigned := false
		for _, r := range rows {
			showSigned = showSigned || r.signed != ""
		}
		tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		if showSigned {
			fmt.Fprintln(tw, "owner/name\tran\tlatest\tsigned (registry's claim)\tchanges")
		} else {
			fmt.Fprintln(tw, "owner/name\tran\tlatest\tchanges")
		}
		for _, r := range rows {
			if showSigned {
				s := r.signed
				if s == "" {
					s = "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.key, r.ran, r.latest, s, r.changes)
			} else {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.key, r.ran, r.latest, r.changes)
			}
		}
		tw.Flush()
	} else {
		fmt.Fprintf(stdout, "all %d %s up to date\n", current, plural(current, "bundle is", "bundles are"))
	}
	if answered == 0 {
		fmt.Fprintln(stderr, "capm outdated: could not check any bundle; see the table above")
		return 1
	}
	return 0
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

const (
	stateCurrent        = iota // latest equals the last run
	stateDiffers               // newer (or different) version found
	stateRegistryAnswer        // the registry answered, but with "gone"/"removed"/"owner changed"
	stateFailed                // could not ask
)

func checkOutdated(c *client.Client, en knownEntry) (outdatedRow, int) {
	owner, name, _ := strings.Cut(en.Key, "/")
	lr := en.Record.LastRun
	row := outdatedRow{key: client.Sanitize(en.Key), ran: client.Sanitize(lr.Version), latest: "-"}

	res, err := resolveChecked(c, owner, name, "latest")
	if err != nil {
		var re *client.RemovedError
		var ae *client.APIError
		switch {
		case errors.As(err, &re):
			row.changes = client.Sanitize(err.Error())
			return row, stateRegistryAnswer
		case errors.As(err, &ae) && ae.Status == 404:
			row.changes = "no longer in the registry"
			return row, stateRegistryAnswer
		}
		row.changes = "could not check: " + client.Sanitize(err.Error())
		return row, stateFailed
	}
	if en.Record.OwnerID > 0 && res.OwnerID > 0 && en.Record.OwnerID != res.OwnerID {
		row.latest = client.Sanitize(res.Version)
		row.changes = fmt.Sprintf("owner changed (pinned id %d, registry reports %d); not compared", en.Record.OwnerID, res.OwnerID)
		return row, stateRegistryAnswer
	}
	if res.Version == lr.Version {
		return row, stateCurrent
	}
	row.latest = client.Sanitize(res.Version)

	md, signedClaim, err := c.MetadataWithSigned(owner, name, res.Version)
	if signedClaim != nil {
		row.signed = signedWord(*signedClaim)
	}
	if err != nil {
		row.changes = "could not fetch the new manifest: " + client.Sanitize(err.Error())
		return row, stateDiffers
	}
	m := &md.Manifest
	if err := m.Validate(); err != nil {
		row.changes = "registry returned an invalid manifest: " + client.Sanitize(firstLine(manifest.DisplaySafe(err.Error())))
		return row, stateDiffers
	}
	if md.Version != res.Version || m.Metadata.Name != name || m.Metadata.Version != res.Version {
		row.changes = "registry metadata does not match the resolved version"
		return row, stateDiffers
	}
	if lr.Manifest == nil {
		row.changes = "unknown (no manifest recorded)"
		return row, stateDiffers
	}
	row.changes = manifest.DiffPermissions(lr.Manifest, m).Summary()
	return row, stateDiffers
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return l
}
