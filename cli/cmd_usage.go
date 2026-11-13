package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/MasonD-007/capm/cli/internal/client"
)

// limitOf renders a limit; 0 means the registry does not enforce one.
func limitOf(n int64, f func(int64) string) string {
	if n == 0 {
		return "unlimited"
	}
	return f(n)
}

func count(n int64) string { return fmt.Sprint(n) }

// usageCmd prints the caller's storage use and the limits that apply to them.
func usageCmd(args []string, stdout, stderr io.Writer, e env) int {
	const use = "usage: capm usage [--owner <org>]"
	fs := flag.NewFlagSet("usage", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var owner string
	fs.StringVar(&owner, "owner", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(stderr, use)
		return 2
	}
	var ownerSet bool
	fs.Visit(func(f *flag.Flag) { ownerSet = ownerSet || f.Name == "owner" })
	if ownerSet && !segRe.MatchString(owner) {
		fmt.Fprintln(stderr, use)
		return 2
	}
	creds, err := loadCreds(e)
	if err != nil {
		fmt.Fprintf(stderr, "capm usage: %v\n", err)
		return 1
	}
	defer warnExpiry(stderr, e, creds)
	u, err := client.New(e.registry, creds.Token).UsageOf(owner)
	if err != nil {
		if client.IsUnsupported(err) {
			fmt.Fprintln(stderr, "capm usage: this registry does not report usage (it is running an older version)")
		} else {
			fmt.Fprintf(stderr, "capm usage: %v\n", err)
		}
		return 1
	}
	storage := humanBytes(u.Bytes)
	if u.MaxBytes > 0 {
		storage += fmt.Sprintf(" of %s (%d%%)", humanBytes(u.MaxBytes), u.Bytes*100/u.MaxBytes)
	} else {
		storage += " (unlimited)"
	}
	bundles := count(u.Bundles)
	if u.MaxBundles > 0 {
		bundles += fmt.Sprintf(" of %d", u.MaxBundles)
	} else {
		bundles += " (unlimited)"
	}
	fmt.Fprintf(stdout, "Storage:             %s\n", storage)
	fmt.Fprintf(stdout, "Bundles:             %s\n", bundles)
	fmt.Fprintf(stdout, "Versions per bundle: %s\n", limitOf(u.MaxBundleVersions, count))
	return 0
}
