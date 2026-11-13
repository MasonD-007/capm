package main

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/MasonD-007/capm/cli/internal/client"
)

const reportUsage = "usage: capm report <user/name[@version]> --reason malware|secrets-exposed|impersonation|other [--details TEXT]"

// reportReasons mirrors the registry's list; checking locally saves a
// round trip and an hourly rate-limit slot.
var reportReasons = []string{"malware", "secrets-exposed", "impersonation", "other"}

const maxReportDetails = 2000

// reportCmd sends an abuse report. It works anonymously; a stored login for
// this registry is sent so the operator can see who reported.
func reportCmd(args []string, stdout, stderr io.Writer, e env) int {
	var pos []string
	var reason, details string
	haveReason := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, hasVal := strings.Cut(a, "=")
		switch {
		case name == "--reason" || name == "--details":
			if !hasVal {
				if i+1 >= len(args) {
					fmt.Fprintf(stderr, "capm report: %s needs a value\n%s\n", name, reportUsage)
					return 2
				}
				i++
				val = args[i]
			}
			if name == "--reason" {
				reason, haveReason = strings.TrimSpace(val), true
			} else {
				details = val
			}
		case strings.HasPrefix(a, "-") && a != "-":
			fmt.Fprintf(stderr, "capm report: unknown flag %q\n%s\n", client.Sanitize(a), reportUsage)
			return 2
		default:
			pos = append(pos, a)
		}
	}
	bad := func(msg string) int {
		fmt.Fprintf(stderr, "capm report: %s\n%s\n", msg, reportUsage)
		return 2
	}
	if len(pos) != 1 {
		return bad("expected one bundle reference")
	}
	owner, name, version, err := adminRef(pos[0])
	if err != nil {
		return bad(err.Error())
	}
	if !haveReason || reason == "" {
		return bad("--reason is required")
	}
	ok := false
	for _, r := range reportReasons {
		ok = ok || r == reason
	}
	if !ok {
		return bad("--reason must be one of: " + strings.Join(reportReasons, ", "))
	}
	details = strings.TrimSpace(details)
	if reason == "other" && details == "" {
		return bad(`--details is required when the reason is "other"`)
	}
	if utf8.RuneCountInString(details) > maxReportDetails {
		return bad(fmt.Sprintf("--details must be at most %d characters", maxReportDetails))
	}

	token := ""
	if creds, err := loadCreds(e); err == nil {
		token = creds.Token
	}
	what := owner + "/" + name
	if version != "" {
		what += "@" + version
	}
	id, err := client.New(e.registry, token).Report(owner, name, version, reason, details)
	if err != nil {
		var ae *client.APIError
		if errors.As(err, &ae) {
			switch {
			case ae.Status == http.StatusTooManyRequests:
				fmt.Fprintln(stderr, "capm report: too many reports from your network; try again later")
				return 1
			case ae.Status == http.StatusNotFound && ae.Msg == "bundle not found":
				fmt.Fprintf(stderr, "capm report: bundle not found: %s\n", client.Sanitize(owner+"/"+name))
				return 1
			case ae.Status == http.StatusNotFound:
				// An unknown route and an unknown bundle both look like 404 on
				// an older registry, so do not claim either.
				fmt.Fprintf(stderr, "capm report: %s does not accept reports: either it is an older registry without reporting, or reporting is switched off. "+
					"If %s exists, contact the registry operator directly.\n", client.Sanitize(e.registry), client.Sanitize(owner+"/"+name))
				return 1
			}
		}
		fmt.Fprintf(stderr, "capm report: %v\n", err)
		return 1
	}
	msg := "Thanks. The registry operator will review your report of " + client.Sanitize(what) + "."
	if id > 0 {
		msg += fmt.Sprintf(" (report %d)", id)
	}
	fmt.Fprintln(stdout, msg)
	return 0
}
