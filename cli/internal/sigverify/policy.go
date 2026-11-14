package sigverify

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
)

// ActionsIssuer is the only OIDC issuer an accepted certificate may carry.
const ActionsIssuer = "https://token.actions.githubusercontent.com"

const githubPrefix = "https://github.com/"

// GitHub naming rules, applied to every value taken from a certificate before
// it is compared or surfaced. Logins: 1-39 ASCII letters, digits and hyphens,
// not starting or ending with a hyphen. Repository names: 1-100 of letters,
// digits, '.', '_' and '-'; "." and ".." are not names.
var (
	loginRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
	repoRe  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
	// A numeric GitHub id: canonical decimal, no sign, no leading zero.
	idRe = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
	// job_workflow_ref: <owner>/<repo>/.github/workflows/<file>@<ref>. The
	// owner/repo/file part is strict; the ref (a branch or tag name, which Git
	// lets contain nearly anything) is sanitised for display, not rejected.
	workflowRe = regexp.MustCompile(`^https://github\.com/([A-Za-z0-9-]{1,39})/([A-Za-z0-9._-]{1,100})/\.github/workflows/([A-Za-z0-9._-]{1,100}\.ya?ml)@(.{1,512})$`)
	runURLRe   = regexp.MustCompile(`^https://github\.com/[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}/actions/runs/[0-9]{1,20}(?:/attempts/[0-9]{1,6})?$`)
	shaRe      = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
)

// parseOwnerURI returns the login of "https://github.com/<login>". The scheme
// and host must be exactly as written (lower case); there must be nothing
// after the login (no slash, query or fragment).
func parseOwnerURI(uri string) (login string, ok bool) {
	login, found := strings.CutPrefix(uri, githubPrefix)
	if !found || !loginRe.MatchString(login) {
		return "", false
	}
	return login, true
}

// parseRepoURI returns the owner and name of "https://github.com/<owner>/<repo>".
func parseRepoURI(uri string) (owner, name string, ok bool) {
	rest, found := strings.CutPrefix(uri, githubPrefix)
	if !found {
		return "", "", false
	}
	owner, name, found = strings.Cut(rest, "/")
	if !found || !loginRe.MatchString(owner) || !repoRe.MatchString(name) || name == "." || name == ".." {
		return "", "", false
	}
	return owner, name, true
}

// parseID parses a numeric GitHub id from a certificate extension.
func parseID(s string) (int64, bool) {
	if !idRe.MatchString(s) {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// workflowRef validates a job_workflow_ref / build signer URI and returns it
// with the ref part sanitised for display.
func workflowRef(uri string) (string, bool) {
	m := workflowRe.FindStringSubmatch(uri)
	if m == nil || !loginRe.MatchString(m[1]) || m[2] == "." || m[2] == ".." {
		return "", false
	}
	return uri[:len(uri)-len(m[4])] + sanitize(m[4], 200), true
}

func validateExpect(w Expect) error {
	if !loginRe.MatchString(w.OwnerLogin) {
		return newErr(ErrInvalidInput, "expected owner login is not a valid GitHub login", nil)
	}
	if w.OwnerID < 0 || w.RepositoryID < 0 {
		return newErr(ErrInvalidInput, "expected ids must not be negative", nil)
	}
	if w.Repository != "" {
		owner, name, ok := strings.Cut(w.Repository, "/")
		if !ok || !loginRe.MatchString(owner) || !repoRe.MatchString(name) || name == "." || name == ".." {
			return newErr(ErrInvalidInput, "expected repository is not of the form owner/repo", nil)
		}
		if !strings.EqualFold(owner, w.OwnerLogin) {
			return newErr(ErrInvalidInput, "expected repository is not owned by the expected owner login", nil)
		}
	}
	return nil
}

// checkIdentity applies the policy to the certificate summary of a signature
// whose cryptography has ALREADY been verified. It is a pure function of its
// arguments.
//
// Owner and repository come from the Fulcio source-repository extensions
// (1.3.6.1.4.1.57264.1.12 / .15 / .16 / .17), not from the SAN: the SAN is the
// job_workflow_ref, which for a reusable workflow names the repository that
// holds the workflow file, not the repository that ran it. The SAN is still
// required to be a well-formed workflow reference (a GitHub Actions
// certificate always has one, so anything else is not what this package
// accepts) and is exposed as Identity.WorkflowRef when the build-signer
// extension is absent. It is deliberately not required to match the source
// repository, so reusable workflows keep working.
func checkIdentity(c certificate.Summary, want Expect) (Identity, error) {
	idErr := func(field, reason, wantV, got string) error {
		return &IdentityError{Field: field, Reason: reason, Want: wantV, Got: got}
	}

	if c.Issuer != ActionsIssuer {
		return Identity{}, idErr("issuer", "mismatch", ActionsIssuer, shownIssuer(c.Issuer))
	}

	// Shapes first: refuse anything that is not a legitimate GitHub value,
	// whether or not the caller asked to compare it, and never echo it.
	ownerLogin, ok := parseOwnerURI(c.SourceRepositoryOwnerURI)
	if !ok {
		return Identity{}, idErr("owner login", "malformed", "", "")
	}
	ownerID, ok := parseID(c.SourceRepositoryOwnerIdentifier)
	if !ok {
		reason := "malformed"
		if c.SourceRepositoryOwnerIdentifier == "" {
			reason = "missing"
		}
		return Identity{}, idErr("owner id", reason, "", "")
	}
	repoOwner, repoName, ok := parseRepoURI(c.SourceRepositoryURI)
	if !ok {
		return Identity{}, idErr("repository", "malformed", "", "")
	}
	repoID, ok := parseID(c.SourceRepositoryIdentifier)
	if !ok {
		reason := "malformed"
		if c.SourceRepositoryIdentifier == "" {
			reason = "missing"
		}
		return Identity{}, idErr("repository id", reason, "", "")
	}
	if !strings.EqualFold(repoOwner, ownerLogin) {
		return Identity{}, idErr("repository", "inconsistent with owner", "", "")
	}
	wf, ok := workflowRef(c.SubjectAlternativeName)
	if !ok {
		return Identity{}, idErr("workflow", "malformed", "", "")
	}
	if c.BuildSignerURI != "" {
		bs, ok := workflowRef(c.BuildSignerURI)
		if !ok {
			return Identity{}, idErr("workflow", "malformed", "", "")
		}
		wf = bs
	}

	// Comparisons. Logins are ASCII by construction (validated above and in
	// validateExpect), so EqualFold has no Unicode surprises such as U+212A.
	if !strings.EqualFold(ownerLogin, want.OwnerLogin) {
		return Identity{}, idErr("owner login", "mismatch", want.OwnerLogin, ownerLogin)
	}
	if want.OwnerID != 0 && ownerID != want.OwnerID {
		return Identity{}, idErr("owner id", "mismatch", strconv.FormatInt(want.OwnerID, 10), strconv.FormatInt(ownerID, 10))
	}
	if want.Repository != "" && !strings.EqualFold(repoOwner+"/"+repoName, want.Repository) {
		return Identity{}, idErr("repository", "mismatch", want.Repository, repoOwner+"/"+repoName)
	}
	if want.RepositoryID != 0 && repoID != want.RepositoryID {
		return Identity{}, idErr("repository id", "mismatch", strconv.FormatInt(want.RepositoryID, 10), strconv.FormatInt(repoID, 10))
	}

	id := Identity{
		Issuer:       c.Issuer,
		OwnerLogin:   ownerLogin,
		OwnerID:      ownerID,
		Repository:   repoOwner + "/" + repoName,
		RepositoryID: repoID,
		WorkflowRef:  wf,
		SourceRef:    sanitize(c.SourceRepositoryRef, 200),
	}
	// Informational fields: surfaced only in their legitimate shape.
	if shaRe.MatchString(c.SourceRepositoryDigest) {
		id.SourceSHA = c.SourceRepositoryDigest
	}
	if runURLRe.MatchString(c.RunInvocationURI) {
		id.RunURL = c.RunInvocationURI
	}
	return id, nil
}

var plainURLRe = regexp.MustCompile(`^https://[A-Za-z0-9._/-]{1,100}$`)

// shownIssuer returns an issuer for an error message only if it is a plain
// https URL; anything else is withheld.
func shownIssuer(s string) string {
	if plainURLRe.MatchString(s) {
		return s
	}
	return ""
}
