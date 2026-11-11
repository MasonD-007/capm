package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/MasonD-007/capm/cli/internal/client"
	"github.com/MasonD-007/capm/manifest"
)

// push packs the bundle directory and publishes it as <login>/<name>@<version>.
func push(args []string, stdout, stderr io.Writer, e env) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: capm push <dir>")
		return 2
	}
	creds, err := loadCreds(e)
	if err != nil {
		fmt.Fprintf(stderr, "capm push: %v\n", err)
		return 1
	}
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
	tarball, err := manifest.PackDir(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "capm push: %v\n", err)
		return 1
	}
	c := client.New(e.registry, creds.Token)
	if err := c.Publish(creds.Login, m.Metadata.Name, m.Metadata.Version, tarball); err != nil {
		fmt.Fprintf(stderr, "capm push: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Published %s/%s@%s\n", creds.Login, m.Metadata.Name, m.Metadata.Version)
	return 0
}
