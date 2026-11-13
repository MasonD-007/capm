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

const lintUse = "usage: capm lint [dir] [--strict] [--offline]"

// printFinding writes one finding as `warning[id]: message` (or error[...]).
func printFinding(w io.Writer, f manifest.Finding) {
	fmt.Fprintf(w, "%s[%s]: %s\n", f.Severity, f.ID, client.Sanitize(f.Message))
}

func countSeverity(fs []manifest.Finding) (errs, warns int) {
	for _, f := range fs {
		if f.Severity == manifest.LintError {
			errs++
		} else {
			warns++
		}
	}
	return
}

// lint checks the bundle in dir beyond plain validity and prints the risk
// labels. Findings and notes go to stderr, the labels to stdout.
func lint(args []string, stdout, stderr io.Writer, e env) int {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var strict, offline bool
	fs.BoolVar(&strict, "strict", false, "")
	fs.BoolVar(&offline, "offline", false, "")
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			fmt.Fprintf(stderr, "capm lint: %v\n%s\n", err, lintUse)
			return 2
		}
		if fs.NArg() == 0 {
			break
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(pos) > 1 {
		fmt.Fprintln(stderr, lintUse)
		return 2
	}
	dir := "."
	if len(pos) == 1 {
		dir = pos[0]
	}

	data, err := os.ReadFile(filepath.Join(dir, manifest.FileName))
	if err != nil {
		fmt.Fprintf(stderr, "capm lint: %s\n", client.Sanitize(err.Error()))
		return 1
	}
	m, err := manifest.Parse(data)
	if err == nil {
		err = m.Validate()
	}
	if err != nil {
		fmt.Fprintf(stderr, "capm lint: invalid manifest:\n%s\n", client.Sanitize(err.Error()))
		return 1
	}

	var found []manifest.Finding
	found = append(found, m.Lint()...)
	files := manifest.PackedFiles(dir, m)
	pre := preflightFindings(files)
	found = append(found, pre...)
	found = append(found, dirFindings(dir, files)...)
	if len(pre) == 0 {
		if tarball, err := manifest.PackDir(dir); err == nil {
			found = append(found, sizeFinding(tarball)...)
		}
	}
	var notes []string
	if offline {
		// no network checks
	} else if f, note := versionFinding(e, m); note != "" {
		notes = append(notes, note)
	} else {
		found = append(found, f...)
	}

	for _, f := range found {
		printFinding(stderr, f)
	}
	for _, n := range notes {
		fmt.Fprintf(stderr, "note: %s\n", client.Sanitize(n))
	}
	errs, warns := countSeverity(found)
	if len(found) == 0 {
		fmt.Fprintln(stderr, "capm lint: no problems found")
	} else {
		fmt.Fprintf(stderr, "%d errors, %d warnings\n", errs, warns)
	}
	fmt.Fprint(stdout, "\n"+manifest.RenderRiskLabels(m.RiskLabels()))
	if errs > 0 || (strict && warns > 0) {
		return 1
	}
	return 0
}

// versionFinding compares the manifest's version with what the registry has
// for the logged-in owner. A non-empty note means the check was skipped; it
// never fails lint. Only "already exists" and "lower than the latest" are
// reported; a bundle unknown to the registry is fine.
func versionFinding(e env, m *manifest.Manifest) ([]manifest.Finding, string) {
	const skipped = "version_not_bumped skipped: "
	creds, err := loadCreds(e)
	if err != nil {
		return nil, skipped + "not logged in (run capm login to compare with the registry, or pass --offline)"
	}
	if creds, err = creds.withLogin(e); err != nil {
		return nil, skipped + err.Error()
	}
	name, version := m.Metadata.Name, m.Metadata.Version
	versions, err := client.New(e.registry, creds.Token).Versions(creds.Login, name)
	if err != nil {
		var ae *client.APIError
		if errors.As(err, &ae) && ae.Status == 404 {
			return nil, "" // not published yet
		}
		return nil, skipped + "registry unavailable: " + err.Error()
	}
	latest := ""
	for _, v := range versions {
		if v.Version == version {
			return []manifest.Finding{{ID: "version_not_bumped", Severity: manifest.LintWarning,
				Message: fmt.Sprintf("version %s already exists on the registry for %s/%s; push would be rejected, bump metadata.version", version, creds.Login, name)}}, ""
		}
		if _, ok := manifest.CompareVersions(v.Version, v.Version); !ok {
			continue // not semver; the registry should never have stored it
		}
		if c, _ := manifest.CompareVersions(v.Version, latest); latest == "" || c > 0 {
			latest = v.Version
		}
	}
	if latest != "" {
		if c, ok := manifest.CompareVersions(version, latest); ok && c < 0 {
			return []manifest.Finding{{ID: "version_not_bumped", Severity: manifest.LintWarning,
				Message: fmt.Sprintf("version %s is lower than the latest published version %s for %s/%s", version, latest, creds.Login, name)}}, ""
		}
	}
	return nil, ""
}
