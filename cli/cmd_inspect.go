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

// inspect prints the declared-permission summary for the bundle in args[0].
func inspect(args []string, stdout, stderr io.Writer, e env) int {
	const use = "usage: capm inspect <dir | user/name[@version]> [--diff [oldversion]]\n(an existing local path wins over a registry reference; use ./user/name to force local)"
	target, diff, oldVersion, ok := parseInspectArgs(args)
	if !ok {
		fmt.Fprintln(stderr, use)
		return 2
	}
	args = []string{target}
	// An existing path is a local bundle; otherwise a well-formed reference is
	// fetched from the registry. Anything containing "@" is meant as a reference.
	if _, err := os.Stat(args[0]); err != nil {
		if o, n, v, perr := parseRef(args[0]); perr == nil {
			return inspectRemote(o, n, v, diff, oldVersion, stdout, stderr, e)
		} else if strings.Contains(args[0], "@") {
			fmt.Fprintf(stderr, "capm inspect: %v\n%s\n", perr, use)
			return 2
		}
	}
	if diff {
		fmt.Fprintf(stderr, "capm inspect: --diff needs a registry reference (user/name[@version])\n%s\n", use)
		return 2
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
	fmt.Fprint(stdout, "\n"+manifest.RenderRiskLabels(m.RiskLabels()))
	return 0
}

// inspectRemote prints the declared permissions of owner/name@spec from the
// registry's metadata endpoint, without downloading the bundle. The registry
// is untrusted, so the manifest is validated here and the summary is computed
// from it locally; the server's own `summary` field is never used.
func inspectRemote(owner, name, spec string, diff bool, oldVersion string, stdout, stderr io.Writer, e env) int {
	c := client.New(e.registry, "")
	res, err := resolveChecked(c, owner, name, spec)
	if err != nil {
		failFetch(stderr, "inspect", err)
		return 1
	}
	md, err := c.Metadata(owner, name, res.Version)
	if err != nil {
		failFetch(stderr, "inspect", err)
		return 1
	}
	m := &md.Manifest
	if err := m.Validate(); err != nil {
		fmt.Fprintf(stderr, "capm inspect: registry returned an invalid manifest:\n%s\n", manifest.DisplaySafe(err.Error()))
		return 1
	}
	if md.Version != res.Version || m.Metadata.Name != name || m.Metadata.Version != res.Version {
		fmt.Fprintf(stderr, "capm inspect: registry metadata does not match %s/%s@%s\n", owner, name, res.Version)
		return 1
	}
	res.Yanked = res.Yanked || md.Yanked
	fmt.Fprintf(stderr, "inspecting registry %s/%s@%s\n", owner, name, res.Version)
	fmt.Fprintln(stderr, "note: metadata only; the bundle was not downloaded, so its digest was not checked")
	warnYanked(stderr, owner, name, res)
	// Read-only: inspect shows the pin status but never records anything.
	ks := newKnownStore(e, stderr)
	rec, recorded := ks.get(e.registry, owner, name)
	fmt.Fprintln(stderr, describePin(pinStatus(rec, recorded, res.OwnerID), rec, recorded))
	if diff {
		return inspectDiff(c, ks, e, owner, name, res, md, oldVersion, stdout, stderr)
	}
	fmt.Fprint(stdout, m.EnforcedSummary().Render())
	fmt.Fprint(stdout, "\n"+manifest.RenderRiskLabels(m.RiskLabels()))
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
