package main

import (
	"errors"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/MasonD-007/capm/cli/internal/client"
)

// roleLabel says what a recorded role means. Both strings come from the
// registry, so unknown values are shown sanitised and unexplained.
func roleLabel(role string) string {
	switch role {
	case "admin":
		return "owner"
	case "member":
		return "member (organisation grants write access)"
	}
	return client.Sanitize(role)
}

// printOrgsCheck reports the registry's organisation check after
// `capm login --orgs`. The registry's own words (note) go to stderr.
func printOrgsCheck(stdout, stderr io.Writer, oc *client.OrgsCheck) {
	if oc == nil {
		fmt.Fprintln(stderr, "capm login: the registry did not report an organisation check; run capm orgs to see what is recorded")
		return
	}
	if len(oc.Recorded) == 0 {
		fmt.Fprintln(stdout, "No organisations were found where you may publish.")
		fmt.Fprintln(stdout, "(Organisation owners, and members of organisations whose base permission is write, qualify.)")
	} else {
		fmt.Fprintln(stdout, "You may now publish under these organisations (use capm push --owner <org>):")
		for _, o := range oc.Recorded {
			fmt.Fprintf(stdout, "  %s  %s\n", client.Sanitize(o.Org), roleLabel(o.Role))
		}
		fmt.Fprintln(stdout, "This lasts 24 hours; run capm login --orgs again to refresh it (it also drops organisations you have left).")
	}
	if oc.Note != "" {
		fmt.Fprintf(stderr, "note from the registry: %s\n", client.Sanitize(oc.Note))
	}
}

// orgsCmd lists the organisations the registry has recorded for the caller.
func orgsCmd(args []string, stdout, stderr io.Writer, e env) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: capm orgs")
		return 2
	}
	creds, err := loadCreds(e)
	if err != nil {
		fmt.Fprintf(stderr, "capm orgs: %v\n", err)
		return 1
	}
	defer warnExpiry(stderr, e, creds)
	list, err := client.New(e.registry, creds.Token).Orgs()
	if err != nil {
		var ae *client.APIError
		switch {
		case client.IsUnsupported(err):
			fmt.Fprintln(stderr, "capm orgs: this registry does not support organisations (it is running an older version)")
		case errors.As(err, &ae) && ae.Status == 403 && creds.fromEnv:
			fmt.Fprintln(stderr, "capm orgs: CAPM_TOKEN is a publish-only CI token; it cannot list organisations")
		default:
			fmt.Fprintf(stderr, "capm orgs: %v\n", err)
		}
		return 1
	}
	if len(list) == 0 {
		fmt.Fprintln(stdout, "No organisations recorded. Run capm login --orgs to record the ones you may publish under.")
		return 0
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ORGANISATION\tROLE\tVALID UNTIL")
	stale := false
	for _, o := range list {
		until := o.ExpiresAt.Local().Format("2006-01-02 15:04")
		if o.Expired {
			until = "expired"
			stale = true
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", client.Sanitize(o.Org), roleLabel(o.Role), until)
	}
	tw.Flush()
	if stale {
		fmt.Fprintln(stderr, "some records have expired; run capm login --orgs again to refresh them")
	}
	return 0
}
