package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/MasonD-007/capm/manifest"
)

// inspect prints the enforced permission summary for the bundle in args[0].
func inspect(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintf(stderr, "usage: capm inspect <dir>\n")
		return 2
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
