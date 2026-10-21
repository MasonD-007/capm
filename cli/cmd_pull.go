package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/MasonD-007/capm/cli/internal/client"
	"github.com/MasonD-007/capm/manifest"
)

// fetch resolves spec and downloads the bundle, checking the digest when the
// registry supplies one.
func fetch(c *client.Client, owner, name, spec string) ([]byte, client.Resolved, error) {
	res, err := c.Resolve(owner, name, spec)
	if err != nil {
		return nil, res, err
	}
	b, err := c.Download(owner, name, res.Version)
	if err != nil {
		return nil, res, err
	}
	if want, ok := strings.CutPrefix(res.Digest, "sha256:"); ok {
		sum := sha256.Sum256(b)
		if hex.EncodeToString(sum[:]) != want {
			return nil, res, fmt.Errorf("downloaded bundle does not match its digest %s", res.Digest)
		}
	}
	return b, res, nil
}

func warnYanked(stderr io.Writer, owner, name string, r client.Resolved) {
	if r.Warning == "yanked" || r.Yanked {
		fmt.Fprintf(stderr, "warning: %s/%s@%s has been yanked by its owner; use it with care\n", owner, name, r.Version)
	}
}

// pull downloads user/name[@version] into ./<name>/.
func pull(args []string, stdout, stderr io.Writer, e env) int {
	const use = "usage: capm pull user/name[@version]"
	if len(args) != 1 {
		fmt.Fprintln(stderr, use)
		return 2
	}
	owner, name, spec, err := parseRef(args[0])
	if err != nil {
		fmt.Fprintf(stderr, "capm pull: %v\n%s\n", err, use)
		return 2
	}
	dest := name
	if ents, err := os.ReadDir(dest); err == nil {
		if len(ents) > 0 {
			fmt.Fprintf(stderr, "capm pull: ./%s already exists and is not empty\n", dest)
			return 1
		}
	} else if !os.IsNotExist(err) {
		fmt.Fprintf(stderr, "capm pull: ./%s exists and is not a directory\n", dest)
		return 1
	}
	tarball, res, err := fetch(client.New(e.registry, ""), owner, name, spec)
	if err != nil {
		fmt.Fprintf(stderr, "capm pull: %v\n", err)
		return 1
	}
	// Unpack beside the destination, then rename, so a failure leaves nothing behind.
	tmp, err := os.MkdirTemp(".", ".capm-pull-*")
	if err != nil {
		fmt.Fprintf(stderr, "capm pull: %v\n", err)
		return 1
	}
	defer os.RemoveAll(tmp)
	if _, err := manifest.UnpackTo(tarball, tmp); err != nil {
		fmt.Fprintf(stderr, "capm pull: refusing bundle: %v\n", err)
		return 1
	}
	os.Remove(dest) // succeeds only for an empty directory, which is allowed
	if err := os.Rename(tmp, dest); err != nil {
		fmt.Fprintf(stderr, "capm pull: %v\n", err)
		return 1
	}
	os.Chmod(dest, 0o755)
	warnYanked(stderr, owner, name, res)
	fmt.Fprintf(stdout, "Pulled %s/%s@%s into ./%s\n", owner, name, res.Version, dest)
	return 0
}
