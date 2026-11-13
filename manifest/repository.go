package manifest

import (
	"regexp"
	"strings"
)

// repositoryPrefix is the only accepted form of metadata.repository. It is
// compared byte for byte: no other scheme, host spelling, port or userinfo.
const repositoryPrefix = "https://github.com/"

var (
	// GitHub account names: ASCII letters, digits and hyphens, at most 39
	// characters, not starting with a hyphen.
	repoOwnerRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)
	// Repository names: ASCII letters, digits, '.', '_' and '-', at most 100.
	repoNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
)

// repoParts validates an owner and repository name.
func repoParts(owner, repo string) bool {
	return repoOwnerRe.MatchString(owner) && repoNameRe.MatchString(repo) &&
		repo != "." && repo != ".." && !strings.HasSuffix(strings.ToLower(repo), ".git")
}

// ParseRepository checks that s is exactly https://github.com/<owner>/<repo>
// (https, host github.com in lower case, two path segments of characters
// GitHub allows, no trailing slash, no ".git", no query, fragment, userinfo
// or port) and returns the two segments. Anything else is not ok.
func ParseRepository(s string) (owner, repo string, ok bool) {
	rest, found := strings.CutPrefix(s, repositoryPrefix)
	if !found || len(s) > 200 {
		return "", "", false
	}
	owner, repo, found = strings.Cut(rest, "/")
	if !found || !repoParts(owner, repo) {
		return "", "", false
	}
	return owner, repo, true
}

// RepositoryMatches reports whether the manifest's metadata.repository claim
// names the same repository as ciRepository, the "owner/repo" a GitHub
// Actions identity token certified. Both sides are parsed structurally and
// compared case-insensitively (GitHub names are); a claim or a certified
// value of any other shape never matches.
func RepositoryMatches(claim, ciRepository string) bool {
	co, cr, ok := ParseRepository(claim)
	if !ok {
		return false
	}
	to, tr, found := strings.Cut(ciRepository, "/")
	if !found || !repoParts(to, tr) {
		return false
	}
	return strings.EqualFold(co, to) && strings.EqualFold(cr, tr)
}
