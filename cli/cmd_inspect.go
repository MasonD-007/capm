package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/MasonD-007/capm/cli/internal/client"
	"github.com/MasonD-007/capm/manifest"
)

// inspect prints the enforced permission summary for the bundle in args[0].
func inspect(args []string, stdout, stderr io.Writer, e env) int {
	if len(args) != 1 {
		fmt.Fprintf(stderr, "usage: capm inspect <dir | user/name[@version]>\n(an existing local path wins over a registry reference; use ./user/name to force local)\n")
		return 2
	}
	// An existing path is a local bundle; otherwise a well-formed reference is
	// fetched from the registry. Anything containing "@" is meant as a reference.
	if _, err := os.Stat(args[0]); err != nil {
		if o, n, v, perr := parseRef(args[0]); perr == nil {
			return inspectRemote(o, n, v, stdout, stderr, e)
		} else if strings.Contains(args[0], "@") {
			fmt.Fprintf(stderr, "capm inspect: %v\nusage: capm inspect <dir | user/name[@version]>\n(an existing local path wins over a registry reference; use ./user/name to force local)\n", perr)
			return 2
		}
	}
	fmt.Fprintf(stderr, "inspecting local %s\n", client.Sanitize(args[0]))
	data, err := os.ReadFile(filepath.Join(args[0], manifest.FileName))
	if err != nil {
		fmt.Fprintf(stderr, "capm inspect: %v\n", err)
		return 1
	}
	m, err := manifest.Parse(data)
	if err == nil {
		err = m.Validate()
	}
	if err != nil {
		fmt.Fprintf(stderr, "capm inspect: invalid manifest:\n%v\n", err)
		return 1
	}
	fmt.Fprint(stdout, m.EnforcedSummary().Render())
	return 0
}

func inspectRemote(owner, name, spec string, stdout, stderr io.Writer, e env) int {
	m, tmp, res, err := fetchToTemp(e, owner, name, spec, "", "capm-inspect-*")
	if tmp != "" {
		defer os.RemoveAll(tmp)
	}
	if err != nil {
		fmt.Fprintf(stderr, "capm inspect: %v\n", err)
		return 1
	}
	fmt.Fprintf(stderr, "inspecting registry %s/%s@%s\n", owner, name, res.Version)
	warnYanked(stderr, owner, name, res)
	fmt.Fprint(stdout, m.EnforcedSummary().Render())
	return 0
}

// fetchToTemp downloads owner/name@spec and unpacks it into a new directory
// under root (os.TempDir() when ""). The caller removes the returned
// directory whenever it is non-empty, including on error.
func fetchToTemp(e env, owner, name, spec, root, pattern string) (*manifest.Manifest, string, client.Resolved, error) {
	tarball, res, err := fetch(client.New(e.registry, ""), owner, name, spec)
	if err != nil {
		return nil, "", res, err
	}
	tmp, err := os.MkdirTemp(root, pattern)
	if err != nil {
		return nil, "", res, err
	}
	m, err := manifest.UnpackTo(tarball, tmp)
	if err != nil {
		return nil, tmp, res, fmt.Errorf("invalid bundle: %w", err)
	}
	return m, tmp, res, nil
}
