package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/MasonD-007/capm/manifest"
)

const (
	maxBinaryBytes    = 200 << 20
	maxChecksumsBytes = 1 << 20
)

var sha256HexRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// packageManagerMarkers in an executable path mean a package manager owns the
// file; replacing it behind the manager's back would be overwritten or
// confuse it.
var packageManagerMarkers = []string{"/Cellar/", "/homebrew/", "/nix/store/"}

func packageManagerPath(p string) bool {
	for _, m := range packageManagerMarkers {
		if strings.Contains(p, m) {
			return true
		}
	}
	return false
}

// checksumFor finds asset's SHA-256 in checksums.txt text ("<hex>  <name>",
// "<hex> *<name>" for binary mode).
func checksumFor(txt, asset string) (string, bool) {
	for _, line := range strings.Split(txt, "\n") {
		f := strings.Fields(line)
		if len(f) != 2 || !sha256HexRe.MatchString(strings.ToLower(f[0])) {
			continue
		}
		if f[1] == asset || f[1] == "*"+asset {
			return strings.ToLower(f[0]), true
		}
	}
	return "", false
}

// httpGet fetches url (capped at max bytes). A non-2xx status is an error.
func (e env) httpGet(ctx context.Context, url string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", e.userAgent())
	resp, err := e.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("GET %s: %s", manifest.DisplaySafe(url), resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("GET %s: response exceeds %d bytes", manifest.DisplaySafe(url), max)
	}
	return b, nil
}

// selfUpdate implements `capm self-update [--check]`.
func selfUpdate(args []string, stdout, stderr io.Writer, e env) int {
	const use = "usage: capm self-update [--check]"
	check := false
	for _, a := range args {
		if a != "--check" || check {
			fmt.Fprintln(stderr, use)
			return 2
		}
		check = true
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "capm self-update: "+format+"\n", a...)
		return 1
	}
	ctx := e.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	goos, goarch := e.upd.goos, e.upd.goarch
	if goos == "" {
		goos = runtime.GOOS
	}
	if goarch == "" {
		goarch = runtime.GOARCH
	}

	var exe string
	if !check {
		if (goos != "darwin" && goos != "linux") || (goarch != "amd64" && goarch != "arm64") {
			return fail("%s/%s is not supported; capm releases are built for macOS and Linux on amd64 and arm64", goos, goarch)
		}
		path, err := e.executablePath()
		if err != nil {
			return fail("cannot find the running executable: %v", err)
		}
		const pm = "%s looks like it is managed by a package manager (Homebrew or Nix); update capm with that package manager instead"
		if packageManagerPath(path) {
			return fail(pm, path)
		}
		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			return fail("cannot resolve %s: %v", path, err)
		}
		if packageManagerPath(real) {
			return fail(pm, real)
		}
		exe = real
	}

	latest, err := latestVersion(ctx, e.httpClient(), e.latestURL(), e.userAgent())
	if err != nil {
		return fail("%v", err)
	}
	newer, known := isNewer(version, latest)
	cur, lat := manifest.DisplaySafe(version), manifest.DisplaySafe(latest)

	if check {
		fmt.Fprintf(stdout, "current %s latest %s\n", cur, lat)
		switch {
		case !known:
			fmt.Fprintf(stderr, "%s; latest is %s\n", unversioned(), lat)
			if newer {
				fmt.Fprintln(stderr, "an update is available; run capm self-update")
			}
		case newer:
			fmt.Fprintf(stderr, "an update is available (%s -> %s); run capm self-update\n", cur, lat)
		default:
			fmt.Fprintf(stderr, "capm is up to date (%s)\n", cur)
		}
		return 0
	}

	if !newer {
		fmt.Fprintf(stderr, "capm is already up to date (%s)\n", cur)
		return 0
	}
	if !known {
		fmt.Fprintf(stderr, "%s; updating to %s\n", unversioned(), lat)
	} else {
		fmt.Fprintf(stderr, "updating capm %s -> %s\n", cur, lat)
	}

	dir := filepath.Dir(exe)
	probe, err := os.CreateTemp(dir, ".capm-update-*")
	if err != nil {
		return fail("the directory %s is not writable (%v); re-run with permission to write there, or reinstall: curl -fsSL https://capm.masondrake.dev/install.sh | CAPM_INSTALL_DIR=%s sh", dir, err, dir)
	}
	probe.Close()
	os.Remove(probe.Name())

	asset := "capm-" + goos + "-" + goarch
	base := e.downloadBase()
	sums, err := e.httpGet(ctx, base+"/checksums.txt", maxChecksumsBytes)
	if err != nil {
		return fail("%v", err)
	}
	want, ok := checksumFor(string(sums), asset)
	if !ok {
		return fail("checksums.txt has no entry for %s; refusing to update", asset)
	}
	bin, err := e.httpGet(ctx, base+"/"+asset, maxBinaryBytes)
	if err != nil {
		return fail("%v", err)
	}
	sum := sha256.Sum256(bin)
	if got := hex.EncodeToString(sum[:]); got != want {
		fmt.Fprintf(stderr, "capm self-update: checksum mismatch for %s; nothing was changed\n  expected: %s\n  actual:   %s\n", asset, want, got)
		return 1
	}

	if err := replaceExecutable(exe, bin); err != nil {
		return fail("%v; the existing capm was left untouched", err)
	}
	fmt.Fprintf(stderr, "installed %s to %s\n", lat, exe)
	out, err := exec.CommandContext(ctx, exe, "version").Output()
	if err != nil {
		fmt.Fprintf(stderr, "warning: the updated binary failed to run %q: %v\n", "version", err)
		return 1
	}
	fmt.Fprint(stdout, string(out))
	return 0
}

func (e env) executablePath() (string, error) {
	if e.upd.exePath != nil {
		return e.upd.exePath()
	}
	return os.Executable()
}

// replaceExecutable writes data next to dst (same directory, so the rename
// cannot cross filesystems), marks it 0755 and renames it over dst. dst is
// either replaced whole or left as it was; the temp file never survives.
func replaceExecutable(dst string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(dst), ".capm-update-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), dst); err != nil {
		return err
	}
	return nil
}

