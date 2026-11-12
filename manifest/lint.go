package manifest

import (
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

// Lint severities.
const (
	LintError   = "error"
	LintWarning = "warning"
)

// PublishLimit is the registry's default cap on one uploaded bundle (5 MiB;
// the backend reads MAX_BUNDLE_BYTES, so a private registry may differ). The
// CLI uses it only to warn before a bundle gets close.
const PublishLimit = 5 << 20

// Finding is one lint result. Messages never contain manifest-controlled
// strings; callers still pass them through a sanitiser before printing.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// Lint returns the findings that need only the manifest, in a fixed order.
// It assumes the manifest has already passed Validate.
func (m *Manifest) Lint() []Finding {
	var out []Finding
	if strings.TrimSpace(m.Metadata.Description) == "" {
		out = append(out, Finding{"no_description", LintWarning,
			"metadata.description is empty; the registry and capm list show it to people deciding whether to run this bundle"})
	}
	if len(m.Metadata.Authors) == 0 {
		out = append(out, Finding{"no_authors", LintWarning,
			"metadata.authors is empty; say who maintains this bundle"})
	}
	return out
}

// PackedFile is one file PackDir would put in the tarball. Err is set when
// the file cannot be packed (missing, symlink, not a regular file, too large).
type PackedFile struct {
	Name string // slash-separated, relative to the bundle root
	Data []byte
	Err  error
}

// PackedFiles lists, in PackDir's order, exactly the files PackDir would
// pack for m in dir: capm.yaml, a regular root README.md, then the listed
// context files (duplicates once). It reads them with PackDir's own rules.
// Problems are reported per file instead of aborting.
func PackedFiles(dir string, m *Manifest) []PackedFile {
	var out []PackedFile
	seen := map[string]bool{}
	add := func(name string) {
		seen[name] = true
		data, err := readRegular(dir, name)
		out = append(out, PackedFile{Name: name, Data: data, Err: err})
	}
	add(FileName)
	if fi, err := os.Lstat(filepath.Join(dir, ReadmeName)); err == nil && fi.Mode().IsRegular() {
		add(ReadmeName)
	}
	for _, rel := range m.Context {
		name := path.Clean(filepath.ToSlash(rel))
		if seen[name] {
			continue
		}
		add(name)
	}
	return out
}

// CompareVersions orders two semver 2.0 versions by precedence (build
// metadata ignored): -1, 0 or 1. ok is false when either is not a plain
// MAJOR.MINOR.PATCH[-pre][+build] version.
func CompareVersions(a, b string) (c int, ok bool) {
	x, ok1 := parseSemver(a)
	y, ok2 := parseSemver(b)
	if !ok1 || !ok2 {
		return 0, false
	}
	return x.compare(y), true
}

type semver struct {
	major, minor, patch uint64
	pre                 []string
}

func parseSemver(s string) (semver, bool) {
	if !semverRe.MatchString(s) {
		return semver{}, false
	}
	s, _, _ = strings.Cut(s, "+")
	core, pre, hasPre := strings.Cut(s, "-")
	var n [3]uint64
	for i, p := range strings.Split(core, ".") {
		v, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return semver{}, false
		}
		n[i] = v
	}
	v := semver{major: n[0], minor: n[1], patch: n[2]}
	if hasPre {
		v.pre = strings.Split(pre, ".")
	}
	return v, true
}

func cmpU(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (a semver) compare(b semver) int {
	for _, c := range []int{cmpU(a.major, b.major), cmpU(a.minor, b.minor), cmpU(a.patch, b.patch)} {
		if c != 0 {
			return c
		}
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		xn, xerr := strconv.ParseUint(x, 10, 64)
		yn, yerr := strconv.ParseUint(y, 10, 64)
		switch {
		case xerr == nil && yerr == nil:
			if c := cmpU(xn, yn); c != 0 {
				return c
			}
		case xerr == nil:
			return -1
		case yerr == nil:
			return 1
		default:
			if c := strings.Compare(x, y); c != 0 {
				return c
			}
		}
	}
	return cmpU(uint64(len(a.pre)), uint64(len(b.pre)))
}

// BaseAgents lists the base agents Validate accepts.
var BaseAgents = []string{"claude-code", "opencode"}

// ValidHost reports whether h is acceptable in permissions.egress.
func ValidHost(h string) bool {
	return len(h) <= 253 && hostRe.MatchString(h) && hasAlpha.MatchString(h)
}

// ValidName reports whether s is acceptable as a bundle or MCP server name.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// ValidSecretName reports whether s is acceptable as a secret name.
func ValidSecretName(s string) bool { return secretRe.MatchString(s) }

// ValidMountPath reports whether p is acceptable as a mount path.
func ValidMountPath(p string) bool { return localPath(p) }
