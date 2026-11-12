package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/MasonD-007/capm/cli/internal/client"
	"github.com/MasonD-007/capm/manifest"
)

// push packs the bundle directory and publishes it as <login>/<name>@<version>.
func push(args []string, stdout, stderr io.Writer, e env) int {
	const use = "usage: capm push [--allow-secret-files] <dir>"
	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var allowSecrets bool
	fs.BoolVar(&allowSecrets, "allow-secret-files", false, "")
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			fmt.Fprintf(stderr, "capm push: %v\n%s\n", err, use)
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) != 1 {
		fmt.Fprintln(stderr, use)
		return 2
	}
	args = pos
	creds, err := loadCreds(e)
	if err != nil {
		fmt.Fprintf(stderr, "capm push: %v\n", err)
		return 1
	}
	defer warnExpiry(stderr, e, creds)
	data, err := os.ReadFile(filepath.Join(args[0], manifest.FileName))
	if err != nil {
		fmt.Fprintf(stderr, "capm push: %v\n", err)
		return 1
	}
	m, err := manifest.Parse(data)
	if err == nil {
		err = m.Validate()
	}
	if err != nil {
		fmt.Fprintf(stderr, "capm push: invalid manifest:\n%v\n", err)
		return 1
	}
	if !preflight(args[0], m, allowSecrets, stderr) {
		return 1
	}
	tarball, err := manifest.PackDir(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "capm push: %v\n", err)
		return 1
	}
	c := client.New(e.registry, creds.Token)
	if err := c.Publish(creds.Login, m.Metadata.Name, m.Metadata.Version, tarball); err != nil {
		// A quota rejection carries a sentence written for the publisher
		// (what limit, how much used); show it as is rather than as an HTTP
		// error. The oversized-upload 413 has no limit and stays generic.
		var ae *client.APIError
		if errors.As(err, &ae) && ae.Limit != "" {
			fmt.Fprintf(stderr, "capm push: %s\n", client.Sanitize(ae.Msg))
			return 1
		}
		fmt.Fprintf(stderr, "capm push: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Published %s/%s@%s\n", creds.Login, m.Metadata.Name, m.Metadata.Version)
	return 0
}

// preflight runs the error-level lint checks (context_missing, secret_file)
// before anything is packed or sent. With allowSecrets, secret_file findings
// are printed as warnings and do not block. It reports whether to go on.
func preflight(dir string, m *manifest.Manifest, allowSecrets bool, stderr io.Writer) bool {
	blocked, secretBlocked := 0, false
	for _, f := range preflightFindings(manifest.PackedFiles(dir, m)) {
		if allowSecrets && f.ID == "secret_file" {
			f.Severity = manifest.LintWarning
		} else {
			blocked++
			secretBlocked = secretBlocked || f.ID == "secret_file"
		}
		printFinding(stderr, f)
	}
	if blocked == 0 {
		return true
	}
	fmt.Fprintf(stderr, "capm push: refusing to publish: %d problem(s) above; nothing was sent\n", blocked)
	if secretBlocked {
		fmt.Fprintln(stderr, "(if those files are meant to be public, pass --allow-secret-files)")
	}
	return false
}
