package main

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/MasonD-007/capm/cli/internal/client"
	"github.com/MasonD-007/capm/manifest"
)

// secretPattern is one high-confidence credential shape. The table is the
// single place patterns are defined; every entry has a test.
type secretPattern struct {
	name string
	re   *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{"github-token", regexp.MustCompile(`ghp_[A-Za-z0-9]{36,}`)},
	{"github-fine-grained-token", regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`)},
	{"aws-access-key-id", regexp.MustCompile(`(?:^|[^A-Za-z0-9])AKIA[0-9A-Z]{16}(?:[^A-Za-z0-9]|$)`)},
	{"slack-token", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`)},
	{"anthropic-api-key", regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`)},
	{"private-key", regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----`)},
}

type secretHit struct {
	line    int
	pattern string
}

// maxScanSize bounds the content scan of one file; larger files are skipped
// (bundle files over 8 MiB cannot be packed anyway).
const maxScanSize = 1 << 20

// scanSecrets reports, per pattern, the first line of data that matches.
// Binary data (a NUL in the first 8 KiB) is skipped. It never returns the
// matched text.
func scanSecrets(data []byte) []secretHit {
	if len(data) > maxScanSize {
		return nil
	}
	head := data
	if len(head) > 8192 {
		head = head[:8192]
	}
	if bytes.IndexByte(head, 0) >= 0 {
		return nil
	}
	var hits []secretHit
	done := map[string]bool{}
	for i, line := range bytes.Split(data, []byte("\n")) {
		for _, p := range secretPatterns {
			if !done[p.name] && p.re.Match(line) {
				done[p.name] = true
				hits = append(hits, secretHit{i + 1, p.name})
			}
		}
	}
	return hits
}

// credentialName returns a label when a file with this base name usually
// holds a credential, else "". Template names (.env.example ...) are fine.
func credentialName(base string) string {
	l := strings.ToLower(base)
	switch {
	case l == ".env":
		return ".env"
	case strings.HasPrefix(l, ".env."):
		switch l[len(".env."):] {
		case "example", "sample", "template":
			return ""
		}
		return ".env.*"
	case strings.HasSuffix(l, ".pem"):
		return "*.pem"
	case strings.HasSuffix(l, ".key"):
		return "*.key"
	case l == "id_rsa", l == "id_ed25519", l == "credentials.json", l == ".npmrc", l == ".netrc":
		return l
	}
	return ""
}

func shown(s string) string { return client.Sanitize(s) }

// packProblem explains why a file cannot be packed, without echoing the
// absolute path the OS error carries.
func packProblem(err error) string {
	switch s := err.Error(); {
	case errors.Is(err, fs.ErrNotExist):
		return "does not exist"
	case strings.Contains(s, "symlink"):
		return "is or traverses a symlink"
	case strings.Contains(s, "not a regular file"):
		return "is not a regular file"
	case strings.Contains(s, "too large"):
		return "is larger than the 8 MiB per-file limit"
	}
	return "cannot be read"
}

// preflightFindings runs the error-level checks over the files PackDir would
// pack: context_missing and secret_file. files comes from manifest.PackedFiles.
func preflightFindings(files []manifest.PackedFile) []manifest.Finding {
	var out []manifest.Finding
	for _, f := range files {
		if f.Err != nil {
			out = append(out, manifest.Finding{ID: "context_missing", Severity: manifest.LintError,
				Message: fmt.Sprintf("%q cannot be packed: it %s", shown(f.Name), packProblem(f.Err))})
			continue
		}
		if label := credentialName(filepath.Base(f.Name)); label != "" {
			out = append(out, manifest.Finding{ID: "secret_file", Severity: manifest.LintError,
				Message: fmt.Sprintf("%s would be published and its file name looks like a credential file (%s)", shown(f.Name), label)})
		}
		for _, h := range scanSecrets(f.Data) {
			out = append(out, manifest.Finding{ID: "secret_file", Severity: manifest.LintError,
				Message: fmt.Sprintf("%s:%d would be published and contains what looks like a credential (%s); the value is not shown", shown(f.Name), h.line, h.pattern)})
		}
	}
	return out
}

const (
	maxUnlistedShown = 10
	maxNearbyScans   = 500 // content scans of unpacked files per run
)

// dirFindings walks dir for files that PackDir would not pack: unlisted files
// (context_unlisted) and credential-looking ones (secret_file_nearby).
// Dot-directories such as .git are skipped.
func dirFindings(dir string, files []manifest.PackedFile) []manifest.Finding {
	packed := map[string]bool{}
	for _, f := range files {
		packed[f.Name] = true
	}
	var unlisted, nearby []manifest.Finding
	nUnlisted, scans := 0, 0
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != dir && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if packed[rel] {
			return nil
		}
		label := credentialName(d.Name())
		pattern := ""
		if label == "" && d.Type().IsRegular() && scans < maxNearbyScans {
			scans++
			if data, err := os.ReadFile(p); err == nil {
				if h := scanSecrets(data); len(h) > 0 {
					pattern = fmt.Sprintf("line %d, %s", h[0].line, h[0].pattern)
				}
			}
		}
		switch {
		case label != "" || pattern != "":
			why := "its file name looks like a credential file (" + label + ")"
			if label == "" {
				why = "it contains what looks like a credential (" + pattern + "; the value is not shown)"
			}
			nearby = append(nearby, manifest.Finding{ID: "secret_file_nearby", Severity: manifest.LintWarning,
				Message: fmt.Sprintf("%s is not published but sits next to the bundle: %s", shown(rel), why)})
		default:
			if nUnlisted++; nUnlisted <= maxUnlistedShown {
				unlisted = append(unlisted, manifest.Finding{ID: "context_unlisted", Severity: manifest.LintWarning,
					Message: fmt.Sprintf("%s is in the bundle directory but not listed in context, so it is NOT published", shown(rel))})
			}
		}
		return nil
	})
	if nUnlisted > maxUnlistedShown {
		unlisted = append(unlisted, manifest.Finding{ID: "context_unlisted", Severity: manifest.LintWarning,
			Message: fmt.Sprintf("and %d more unlisted files (NOT published)", nUnlisted-maxUnlistedShown)})
	}
	return append(unlisted, nearby...)
}

// sizeFinding warns when the packed bundle is over 80% of the publish limit.
func sizeFinding(tarball []byte) []manifest.Finding {
	n := int64(len(tarball))
	if n*10 <= manifest.PublishLimit*8 {
		return nil
	}
	return []manifest.Finding{{ID: "size_near_limit", Severity: manifest.LintWarning,
		Message: fmt.Sprintf("the packed bundle is %.1f MiB, %d%% of the %d MiB publish limit",
			float64(n)/(1<<20), n*100/manifest.PublishLimit, manifest.PublishLimit>>20)}}
}
