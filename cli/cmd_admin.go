package main

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/MasonD-007/capm/cli/internal/client"
)

// adminUsage is shown by `capm admin`; the main usage text does not list the
// command, because only registry admins can use it.
const adminUsage = `capm admin: registry administration (admins only)

Usage:
  capm admin remove  <owner/name[@version]> --reason TEXT   take down a version, or the whole bundle if no version is given
  capm admin restore <owner/name[@version]>                 undo a removal (fails if the data was already deleted)
  capm admin ban     <login|id> --reason TEXT               block a user and hide their bundles
  capm admin unban   <login|id>                             lift a ban
  capm admin revoke-tokens <login|id>                       revoke every login token of a user (they must log in again)
  capm admin quota   <login|id> [--bytes SIZE] [--bundles N] [--reset]
                                                            show a user's storage use and limits; set per-user limits
                                                            (SIZE like 500MiB or 2GiB; 0 = unlimited; --reset restores the defaults)
  capm admin log                                            show the audit log of admin actions

Admins are GitHub numeric ids configured on the registry (ADMIN_GITHUB_IDS).
Run capm login first.
`

// adminArgs splits args into positionals and --reason (either "--reason X" or
// "--reason=X"); any other flag is an error.
func adminArgs(args []string) (pos []string, reason string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--reason":
			if i+1 >= len(args) {
				return nil, "", errors.New("--reason needs a value")
			}
			i++
			reason = args[i]
		case strings.HasPrefix(a, "--reason="):
			reason = strings.TrimPrefix(a, "--reason=")
		case strings.HasPrefix(a, "-") && a != "-":
			return nil, "", fmt.Errorf("unknown flag %q", client.Sanitize(a))
		default:
			pos = append(pos, a)
		}
	}
	return pos, strings.TrimSpace(reason), nil
}

// adminRef parses owner/name or owner/name@version; version is "" for the
// whole bundle.
func adminRef(s string) (owner, name, version string, err error) {
	if strings.HasSuffix(s, "@latest") {
		return "", "", "", errors.New("\"latest\" is not a version: omit @version to act on the whole bundle")
	}
	owner, name, version, err = parseRef(s)
	if err != nil {
		return
	}
	if !strings.Contains(s, "@") {
		version = ""
	}
	return
}

func admin(args []string, stdout, stderr io.Writer, e env) int {
	if len(args) == 0 {
		fmt.Fprint(stdout, adminUsage)
		return 0
	}
	sub := args[0]
	if sub == "quota" {
		return adminQuota(args[1:], stdout, stderr, e)
	}
	pos, reason, err := adminArgs(args[1:])
	bad := func(msg string) int {
		fmt.Fprintf(stderr, "capm admin %s: %s\n\n%s", sub, msg, adminUsage)
		return 2
	}
	switch sub {
	case "remove", "restore", "ban", "unban", "revoke-tokens", "log":
	default:
		fmt.Fprintf(stderr, "capm admin: unknown subcommand %q\n\n%s", client.Sanitize(sub), adminUsage)
		return 2
	}
	if err != nil {
		return bad(err.Error())
	}
	want := 1
	if sub == "log" {
		want = 0
	}
	if len(pos) != want {
		return bad(fmt.Sprintf("expected %d argument(s), got %d", want, len(pos)))
	}
	needReason := sub == "remove" || sub == "ban"
	if needReason && reason == "" {
		return bad("--reason is required")
	}
	if !needReason && reason != "" {
		return bad("--reason is not accepted here")
	}
	var owner, name, version string
	if sub == "remove" || sub == "restore" {
		if owner, name, version, err = adminRef(pos[0]); err != nil {
			return bad(err.Error())
		}
	}

	creds, err := loadCreds(e)
	if err != nil {
		fmt.Fprintf(stderr, "capm admin: %v\n", err)
		return 1
	}
	defer warnExpiry(stderr, e, creds)
	c := client.New(e.registry, creds.Token)
	what := func() string {
		if version == "" {
			return owner + "/" + name
		}
		return owner + "/" + name + "@" + version
	}

	var res client.AdminResult
	var revoked int
	switch sub {
	case "remove":
		res, err = c.AdminRemove(owner, name, version, reason)
	case "restore":
		res, err = c.AdminRestore(owner, name, version)
	case "ban":
		err = c.AdminBan(pos[0], reason)
	case "unban":
		err = c.AdminUnban(pos[0])
	case "revoke-tokens":
		revoked, err = c.AdminRevokeTokens(pos[0])
	case "log":
		var log []client.AdminAction
		if log, err = c.AdminLog(50); err == nil {
			if len(log) == 0 {
				fmt.Fprintln(stderr, "no admin actions recorded")
				return 0
			}
			tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
			for _, a := range log {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", client.Sanitize(a.CreatedAt.UTC().Format("2006-01-02 15:04:05")),
					client.Sanitize(a.Admin), client.Sanitize(a.Action), client.Sanitize(a.Target), client.Sanitize(a.Reason))
			}
			tw.Flush()
			return 0
		}
	}
	if err != nil {
		var ae *client.APIError
		if errors.As(err, &ae) && ae.Status == 404 {
			// The registry answers 404 to non-admins so the surface is not
			// advertised; it is also the answer for an unknown target.
			fmt.Fprintln(stderr, "capm admin: not found (are you an admin on this registry?)")
			return 1
		}
		fmt.Fprintf(stderr, "capm admin %s: %v\n", sub, err)
		return 1
	}
	switch sub {
	case "remove":
		fmt.Fprintf(stdout, "Removed %s (%d version(s); %d blob(s) deleted)\n", what(), len(res.Versions), res.BlobsDeleted)
	case "restore":
		fmt.Fprintf(stdout, "Restored %s", what())
		if len(res.Skipped) > 0 {
			fmt.Fprintf(stdout, " (%d version(s) skipped: data already deleted)", len(res.Skipped))
		}
		fmt.Fprintln(stdout)
	case "ban":
		fmt.Fprintf(stdout, "Banned %s\n", client.Sanitize(pos[0]))
	case "unban":
		fmt.Fprintf(stdout, "Unbanned %s\n", client.Sanitize(pos[0]))
	case "revoke-tokens":
		fmt.Fprintf(stdout, "Revoked %d token(s) for %s\n", revoked, client.Sanitize(pos[0]))
	}
	return 0
}
