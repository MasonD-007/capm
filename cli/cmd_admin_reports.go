package main

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/MasonD-007/capm/cli/internal/client"
	"github.com/MasonD-007/capm/manifest"
)

const reportDetailsCol = 60 // runes of the first details line shown in the table

// stripUnsafe drops control, escape, bidi and separator characters from s
// without truncating it (newlines are the caller's business: split first).
func stripUnsafe(s string) string {
	return strings.Map(func(r rune) rune {
		if manifest.IsUnsafeRune(r) {
			return -1
		}
		return r
	}, s)
}

// firstLine is the first non-blank line of attacker-controlled text,
// sanitised and cut to max runes. Splitting happens before sanitising, so a
// line break can never survive into a table cell.
func firstLine(s string, max int) string {
	for _, l := range strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r' || r == ' ' || r == ' ' || r == '\u0085'
	}) {
		if l = strings.TrimSpace(stripUnsafe(l)); l != "" {
			if utf8.RuneCountInString(l) > max {
				l = string([]rune(l)[:max]) + "..."
			}
			return l
		}
	}
	return ""
}

func reportAge(now, t time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "<1m"
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d/time.Minute))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh", int(d/time.Hour))
	}
	return fmt.Sprintf("%dd", int(d/(24*time.Hour)))
}

func reportBundle(r client.ReportInfo) string {
	s := r.Owner + "/" + r.Name
	if r.Version != "" {
		s += "@" + r.Version
	}
	return s
}

// adminReports implements `capm admin reports|report|resolve`.
func adminReports(sub string, args []string, stdout, stderr io.Writer, e env) int {
	bad := func(msg string) int {
		fmt.Fprintf(stderr, "capm admin %s: %s\n\n%s", sub, msg, adminUsage)
		return 2
	}
	var pos []string
	state, note, haveNote := "open", "", false
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case sub == "reports" && a == "--all":
			if state != "open" {
				return bad("use only one of --all and --resolved")
			}
			state = "all"
		case sub == "reports" && a == "--resolved":
			if state != "open" {
				return bad("use only one of --all and --resolved")
			}
			state = "resolved"
		case sub == "resolve" && (a == "--note" || strings.HasPrefix(a, "--note=")):
			if v, ok := strings.CutPrefix(a, "--note="); ok {
				note = v
			} else if i+1 < len(args) {
				i++
				note = args[i]
			} else {
				return bad("--note needs a value")
			}
			haveNote = true
		case strings.HasPrefix(a, "-") && a != "-":
			return bad(fmt.Sprintf("unknown flag %q", client.Sanitize(a)))
		default:
			pos = append(pos, a)
		}
	}
	var id int64
	if sub == "reports" {
		if len(pos) != 0 {
			return bad("expected no arguments")
		}
	} else {
		if len(pos) != 1 {
			return bad("expected a report id")
		}
		n, err := strconv.ParseInt(pos[0], 10, 64)
		if err != nil || n < 1 {
			return bad("the report id must be a positive number")
		}
		id = n
	}
	if sub == "resolve" {
		note = strings.TrimSpace(note)
		if !haveNote || note == "" {
			return bad("--note is required")
		}
		if utf8.RuneCountInString(note) > 500 {
			return bad("--note must be at most 500 characters")
		}
	}

	creds, err := loadCreds(e)
	if err != nil {
		fmt.Fprintf(stderr, "capm admin: %v\n", err)
		return 1
	}
	defer warnExpiry(stderr, e, creds)
	c := client.New(e.registry, creds.Token)
	now := time.Now()
	if e.now != nil {
		now = e.now()
	}

	var out []client.ReportInfo
	var one client.ReportInfo
	switch sub {
	case "reports":
		out, err = c.AdminReports(state, 200)
	case "report":
		one, err = c.AdminReport(id)
	case "resolve":
		err = c.AdminResolveReport(id, note)
	}
	if err != nil {
		var ae *client.APIError
		if errors.As(err, &ae) && ae.Status == 404 {
			fmt.Fprintln(stderr, "capm admin: not found (are you an admin on this registry, and is the id right?)")
			return 1
		}
		fmt.Fprintf(stderr, "capm admin %s: %v\n", sub, err)
		return 1
	}

	switch sub {
	case "resolve":
		fmt.Fprintf(stdout, "Resolved report %d\n", id)
	case "report":
		printReport(stdout, one, now)
	case "reports":
		if len(out) == 0 {
			label := map[string]string{"open": "open ", "resolved": "resolved ", "all": ""}[state]
			fmt.Fprintf(stderr, "no %sreports\n", label)
			return 0
		}
		tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tBUNDLE\tVERSION\tREASON\tAGE\tSTATE\tDETAILS")
		for _, r := range out {
			version := client.Sanitize(r.Version)
			if version == "" {
				version = "-"
			}
			st := client.Sanitize(r.BundleState)
			if r.ResolvedAt != nil {
				st += " (resolved)"
			}
			fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n", r.ID, client.Sanitize(reportBundle(client.ReportInfo{Owner: r.Owner, Name: r.Name})),
				version, client.Sanitize(r.Reason), reportAge(now, r.CreatedAt), st, firstLine(r.Details, reportDetailsCol))
		}
		tw.Flush()
	}
	return 0
}

// printReport shows one report in full. Details keep their line breaks (the
// reader asked for the whole text) but every line is stripped of control and
// bidi characters and indented, so it cannot pass for one of the fields.
func printReport(w io.Writer, r client.ReportInfo, now time.Time) {
	fmt.Fprintf(w, "Report %d (%s ago)\n", r.ID, reportAge(now, r.CreatedAt))
	fmt.Fprintf(w, "  bundle:   %s\n", client.Sanitize(reportBundle(r)))
	fmt.Fprintf(w, "  reason:   %s\n", client.Sanitize(r.Reason))
	fmt.Fprintf(w, "  state:    %s\n", client.Sanitize(r.BundleState))
	who := "anonymous"
	if r.ReporterLoggedIn {
		who = "logged in"
		if r.Reporter != "" {
			who = client.Sanitize(r.Reporter)
		}
	}
	fmt.Fprintf(w, "  reporter: %s\n", who)
	if r.ResolvedAt != nil {
		fmt.Fprintf(w, "  resolved: %s by %s: %s\n", client.Sanitize(r.ResolvedAt.UTC().Format("2006-01-02 15:04")),
			client.Sanitize(r.ResolvedBy), client.Sanitize(r.Resolution))
	}
	fmt.Fprintln(w, "  details (written by the reporter, not verified):")
	for _, l := range strings.Split(strings.NewReplacer("\r\n", "\n", " ", "\n", " ", "\n", "\u0085", "\n", "\r", "\n").Replace(r.Details), "\n") {
		fmt.Fprintf(w, "  | %s\n", stripUnsafe(l))
	}
}
