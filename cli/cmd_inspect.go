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
		fmt.Fprintf(stderr, "usage: capm inspect <dir | user/name[@version]>\n")
		return 2
	}
	// An existing path is a local bundle; otherwise a well-formed reference is
	// fetched from the registry. Anything containing "@" is meant as a reference.
	if _, err := os.Stat(args[0]); err != nil {
		if o, n, v, perr := parseRef(args[0]); perr == nil {
			return inspectRemote(o, n, v, stdout, stderr, e)
		} else if strings.Contains(args[0], "@") {
			fmt.Fprintf(stderr, "capm inspect: %v\nusage: capm inspect <dir | user/name[@version]>\n", perr)
			return 2
		}
	}
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
	tarball, res, err := fetch(client.New(e.registry, ""), owner, name, spec)
	if err != nil {
		fmt.Fprintf(stderr, "capm inspect: %v\n", err)
		return 1
	}
	tmp, err := os.MkdirTemp("", "capm-inspect-*")
	if err != nil {
		fmt.Fprintf(stderr, "capm inspect: %v\n", err)
		return 1
	}
	defer os.RemoveAll(tmp)
	m, err := manifest.UnpackTo(tarball, tmp)
	if err != nil {
		fmt.Fprintf(stderr, "capm inspect: invalid bundle: %v\n", err)
		return 1
	}
	warnYanked(stderr, owner, name, res)
	fmt.Fprint(stdout, m.EnforcedSummary().Render())
	return 0
}
