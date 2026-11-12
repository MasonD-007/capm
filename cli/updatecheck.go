package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/MasonD-007/capm/manifest"
	"golang.org/x/term"
)

// Release discovery shared by `capm self-update` and the once-a-day notice.
//
// The latest version is learned from the redirect GitHub serves at
// https://github.com/MasonD-007/capm/releases/latest, which points at
// .../releases/tag/<tag>. That is an ordinary web request, not the REST API,
// so it does not consume the 60 requests/hour unauthenticated API quota, and
// the redirect response is all we read (it is never followed).

const (
	defaultLatestURL    = "https://github.com/MasonD-007/capm/releases/latest"
	defaultDownloadBase = "https://github.com/MasonD-007/capm/releases/latest/download"

	updateCheckFile     = "update-check.json"
	updateCheckInterval = 24 * time.Hour
	updateCheckTimeout  = 1500 * time.Millisecond
)

// updateEnv holds what the update commands need injected for tests. Zero
// values mean the real thing.
type updateEnv struct {
	hc           *http.Client
	latestURL    string // "" means CAPM_LATEST_URL, else defaultLatestURL
	downloadBase string // "" means CAPM_DOWNLOAD_BASE (as install.sh), else defaultDownloadBase
	exePath      func() (string, error)
	goos, goarch string
	stderrTTY    func() bool
	timeout      time.Duration // update-notice budget; 0 means updateCheckTimeout
}

// getEnv reads an environment variable through the injected getenv.
func (e env) getEnv(k string) string {
	if e.getenv != nil {
		return e.getenv(k)
	}
	return os.Getenv(k)
}

func (e env) latestURL() string {
	if e.upd.latestURL != "" {
		return e.upd.latestURL
	}
	if v := e.getEnv("CAPM_LATEST_URL"); v != "" {
		return v
	}
	return defaultLatestURL
}

func (e env) downloadBase() string {
	b := e.upd.downloadBase
	if b == "" {
		b = e.getEnv("CAPM_DOWNLOAD_BASE")
	}
	if b == "" {
		b = defaultDownloadBase
	}
	return strings.TrimRight(b, "/")
}

func (e env) userAgent() string { return "capm/" + version }

// httpClient returns the injected client, or one that does not follow
// redirects automatically for the latest-version lookup (see latestVersion)
// and times out downloads after two minutes.
func (e env) httpClient() *http.Client {
	if e.upd.hc != nil {
		return e.upd.hc
	}
	return &http.Client{Timeout: 2 * time.Minute}
}

// noRedirect returns a copy of hc that hands back the first redirect response
// instead of following it.
func noRedirect(hc *http.Client) *http.Client {
	c := *hc
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &c
}

var shaVersionRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// normalizeTag turns a release tag into a version string: "v1.2.3" becomes
// "1.2.3" and a per-commit "cli-<sha>" becomes "<sha>". Anything else is
// returned as is.
func normalizeTag(tag string) string {
	if v, ok := strings.CutPrefix(tag, "v"); ok {
		if _, ok := manifest.CompareVersions(v, v); ok {
			return v
		}
	}
	return strings.TrimPrefix(tag, "cli-")
}

// latestVersion asks latestURL which release is the latest. A redirect to
// .../tag/<tag> names it; a 200 whose own URL contains /tag/<tag> does too
// (test servers and mirrors). The tag is untrusted text and is sanitised.
func latestVersion(ctx context.Context, hc *http.Client, latestURL, userAgent string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, latestURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := noRedirect(hc).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	final := req.URL
	switch {
	case resp.StatusCode/100 == 3:
		loc, err := resp.Location()
		if err != nil {
			return "", fmt.Errorf("latest release lookup: redirect without a location")
		}
		final = loc
	case resp.StatusCode/100 != 2:
		return "", fmt.Errorf("latest release lookup: %s", resp.Status)
	}
	p := strings.TrimRight(final.Path, "/")
	i := strings.LastIndex(p, "/tag/")
	if i < 0 {
		return "", fmt.Errorf("latest release lookup: no release tag in %s", sanitizeURL(final))
	}
	tag, err := url.PathUnescape(p[i+len("/tag/"):])
	if err != nil || tag == "" || strings.Contains(tag, "/") {
		return "", fmt.Errorf("latest release lookup: unusable tag in %s", sanitizeURL(final))
	}
	return normalizeTag(tag), nil
}

func sanitizeURL(u *url.URL) string {
	return manifest.DisplaySafe(u.Scheme + "://" + u.Host + u.Path)
}

// isNewer reports whether latest is a newer version than current. Both semver:
// by precedence. A current build that is not semver (dev, a commit SHA) has an
// unknown version, so anything other than itself counts as newer (known is
// false). A semver current build against a non-semver latest (a per-commit
// tag before the first vX.Y.Z release) cannot be compared and is not newer.
func isNewer(current, latest string) (newer, known bool) {
	if c, ok := manifest.CompareVersions(current, latest); ok {
		return c < 0, true
	}
	if _, ok := manifest.CompareVersions(current, current); ok {
		return false, true
	}
	return current != latest, false
}

// unversioned describes a running build that is not a release.
func unversioned() string {
	return fmt.Sprintf("this build (%s) is not a released version, so it is treated as out of date", manifest.DisplaySafe(version))
}

// --- once-a-day notice ----------------------------------------------------

type updateCheckState struct {
	CheckedAt time.Time `json:"checkedAt"`
	Latest    string    `json:"latest"`
}

func (e env) updateCheckPath() string {
	if e.credDir == "" {
		return ""
	}
	return filepath.Join(e.credDir, updateCheckFile)
}

// loadUpdateCheck treats a missing or corrupt file as "never checked".
func (e env) loadUpdateCheck() updateCheckState {
	var st updateCheckState
	p := e.updateCheckPath()
	if p == "" {
		return st
	}
	b, err := os.ReadFile(p)
	if err != nil || json.Unmarshal(b, &st) != nil {
		return updateCheckState{}
	}
	return st
}

// saveUpdateCheck writes the state atomically (temp file in the same
// directory, mode 0600, rename).
func (e env) saveUpdateCheck(st updateCheckState) error {
	p := e.updateCheckPath()
	if p == "" {
		return errors.New("no config directory")
	}
	if err := os.MkdirAll(e.credDir, 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(e.credDir, ".update-check-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// noticeSkipCommands never trigger the notice.
var noticeSkipCommands = map[string]bool{
	"version": true, "self-update": true, "__complete": true,
	"help": true, "-h": true, "--help": true,
}

func (e env) stderrIsTerminal(stderr io.Writer) bool {
	if e.upd.stderrTTY != nil {
		return e.upd.stderrTTY()
	}
	f, ok := stderr.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// noticeAllowed applies every suppression rule that needs no I/O.
func (e env) noticeAllowed(args []string, code int, stderr io.Writer) bool {
	switch {
	case code != 0, len(args) == 0, noticeSkipCommands[args[0]]:
		return false
	case e.getEnv("CAPM_NO_UPDATE_CHECK") != "", e.getEnv("CI") != "":
		return false
	}
	if _, ok := manifest.CompareVersions(version, version); !ok {
		return false
	}
	return e.stderrIsTerminal(stderr)
}

// maybeNotifyUpdate runs after a command has finished. At most once per 24
// hours it asks for the latest release (hard 1.5 s budget, synchronous, every
// error silent) and prints one stderr line when it is newer than this build.
// The attempt is recorded even when it fails, so an offline machine is not
// charged the timeout on every command.
func (e env) maybeNotifyUpdate(args []string, code int, stderr io.Writer) {
	if !e.noticeAllowed(args, code, stderr) {
		return
	}
	now := time.Now
	if e.now != nil {
		now = e.now
	}
	st := e.loadUpdateCheck()
	t := now()
	if !st.CheckedAt.IsZero() && t.Sub(st.CheckedAt) < updateCheckInterval && !t.Before(st.CheckedAt) {
		return
	}
	timeout := e.upd.timeout
	if timeout <= 0 {
		timeout = updateCheckTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	latest, err := latestVersion(ctx, e.httpClient(), e.latestURL(), e.userAgent())
	next := updateCheckState{CheckedAt: t, Latest: st.Latest}
	if err == nil {
		next.Latest = latest
	}
	_ = e.saveUpdateCheck(next)
	if err != nil {
		return
	}
	if newer, _ := isNewer(version, latest); newer {
		fmt.Fprintf(stderr, "a newer capm is available (%s); run capm self-update\n", manifest.DisplaySafe(latest))
	}
}

