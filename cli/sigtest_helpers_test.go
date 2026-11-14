package main

import (
	"crypto/sha256"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/MasonD-007/capm/cli/internal/sigverify"
)

// sigProxy fronts the fake registry and adds the signature endpoint of the
// registry API contract:
//
//	GET /v1/bundles/{owner}/{name}/{version}/signature
//	  200 raw bundle | 404 no signature (and for a server that predates them)
//
// Every other request is passed to the fake registry unchanged. It counts
// requests so tests can prove what was and was not asked.
type sigProxy struct {
	*httptest.Server

	mu      sync.Mutex
	sigs    map[string]sigResp // "owner/name@version"
	sigReqs int
	allReqs int
	auth    []string // Authorization headers seen on signature requests
}

// dropConnection as a status makes the proxy close the connection without answering.
const dropConnection = -1

type sigResp struct {
	code int
	body []byte
}

func newSigProxy(t *testing.T, upstream string) *sigProxy {
	t.Helper()
	u, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	p := &sigProxy{sigs: map[string]sigResp{}}
	rp := httputil.NewSingleHostReverseProxy(u)
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.allReqs++
		p.mu.Unlock()
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) == 6 && parts[0] == "v1" && parts[1] == "bundles" && parts[5] == "signature" {
			p.mu.Lock()
			p.sigReqs++
			p.auth = append(p.auth, r.Header.Get("Authorization"))
			resp, ok := p.sigs[parts[2]+"/"+parts[3]+"@"+parts[4]]
			p.mu.Unlock()
			if !ok {
				resp = sigResp{code: 404, body: []byte(`{"error":"no signature"}`)}
			}
			if resp.code == dropConnection {
				if c, _, err := w.(http.Hijacker).Hijack(); err == nil {
					c.Close()
				}
				return
			}
			w.WriteHeader(resp.code)
			w.Write(resp.body)
			return
		}
		rp.ServeHTTP(w, r)
	}))
	t.Cleanup(p.Close)
	return p
}

func (p *sigProxy) set(owner, name, version string, code int, body []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.sigs[owner+"/"+name+"@"+version] = sigResp{code, body}
}

func (p *sigProxy) counts() (sig, all int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sigReqs, p.allReqs
}

var fakeSigBytes = []byte(`{"fake":"sigstore bundle"}`)

type verifyCall struct {
	sig, digest []byte
	want        sigverify.Expect
}

// fakeVerifier stands in for sigverify.Verify. With honour set it applies the
// identity expectations the way the real policy does (so the CLI's handling of
// a verifier that refuses on a pinned id is exercised); without it the
// verifier answers the same whatever it is asked, which checks that the CLI
// does not depend on the verifier to enforce pins.
type fakeVerifier struct {
	mu     sync.Mutex
	id     sigverify.Identity
	err    error
	honour bool
	calls  []verifyCall
}

func (v *fakeVerifier) verify(sig, digest []byte, want sigverify.Expect) (sigverify.Identity, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls = append(v.calls, verifyCall{append([]byte(nil), sig...), append([]byte(nil), digest...), want})
	if v.err != nil {
		return sigverify.Identity{}, v.err
	}
	if v.honour {
		id := v.id
		mm := func(field string) error {
			return &sigverify.IdentityError{Field: field, Reason: "mismatch"}
		}
		switch {
		case !strings.EqualFold(id.OwnerLogin, want.OwnerLogin):
			return sigverify.Identity{}, mm("owner login")
		case want.OwnerID != 0 && id.OwnerID != want.OwnerID:
			return sigverify.Identity{}, mm("owner id")
		case want.Repository != "" && !strings.EqualFold(id.Repository, want.Repository):
			return sigverify.Identity{}, mm("repository")
		case want.RepositoryID != 0 && id.RepositoryID != want.RepositoryID:
			return sigverify.Identity{}, mm("repository id")
		}
	}
	return v.id, nil
}

func (v *fakeVerifier) callCount() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return len(v.calls)
}

// aliceID is a plausible verified identity for alice/pr-reviewer (owner id 7).
func aliceID() sigverify.Identity {
	return sigverify.Identity{
		Issuer:       sigverify.ActionsIssuer,
		OwnerLogin:   "alice",
		OwnerID:      7,
		Repository:   "alice/pr-reviewer-src",
		RepositoryID: 555,
		WorkflowRef:  "https://github.com/alice/pr-reviewer-src/.github/workflows/publish.yml@refs/tags/v0.1.0",
		SourceRef:    "refs/tags/v0.1.0",
		SourceSHA:    "0123456789abcdef0123456789abcdef01234567",
	}
}

// sigT is a run harness (alice/pr-reviewer@0.1.0, registry owner id 7) behind
// a signature-serving proxy and a fake verifier.
type sigT struct {
	*runHarness
	proxy *sigProxy
	vf    *fakeVerifier
}

func newSigT(t *testing.T, stdin string, tty bool) *sigT {
	t.Helper()
	h := pinHarness(t, stdin, tty)
	p := newSigProxy(t, h.reg.srv.URL)
	h.env.registry = p.URL
	vf := &fakeVerifier{honour: true, id: aliceID()}
	h.env.verify = vf.verify
	return &sigT{runHarness: h, proxy: p, vf: vf}
}

// signed publishes a signature for alice/pr-reviewer@0.1.0.
func (s *sigT) signed() { s.proxy.set("alice", "pr-reviewer", "0.1.0", 200, fakeSigBytes) }

func (s *sigT) pull(extra ...string) int {
	return s.run(append(append([]string{"pull"}, extra...), refTarget)...)
}

func (s *sigT) runBundle(extra ...string) int {
	return s.runArgs(append(append([]string{"--yes", "--allow-unenforced-egress"}, extra...), refTarget)...)
}

func (s *sigT) rec(t *testing.T) (knownRecord, bool) {
	t.Helper()
	return s.knownRecord(t)
}

// seed writes a record as an earlier run would have.
func (s *sigT) seed(t *testing.T, fn func(*knownRecord)) {
	t.Helper()
	if err := newKnownStore(s.env, &strings.Builder{}).update(s.env.registry, "alice", "pr-reviewer", fn); err != nil {
		t.Fatal(err)
	}
}

func (s *sigT) knownFileExists() bool {
	_, err := os.Stat(filepath.Join(s.env.credDir, knownFileName))
	return err == nil
}

func (s *sigT) pulledDirExists() bool {
	_, err := os.Stat("pr-reviewer")
	return err == nil
}

func (s *sigT) stderr() string { return s.errb.String() }

var overclaimRe = regexp.MustCompile(`(?i)\b(verified|valid)\b`)

// assertNoVerifiedClaim fails if any line capm printed about signatures or as
// a refusal says "verified" or "valid" (the whole words; "invalid" and "did not
// verify" are fine). Lines about other subjects are not looked at.
func assertNoVerifiedClaim(t *testing.T, out string) {
	t.Helper()
	for _, l := range strings.Split(out, "\n") {
		low := strings.ToLower(l)
		if strings.Contains(low, "signature") || strings.HasPrefix(low, "capm ") || strings.HasPrefix(low, "warning:") {
			if overclaimRe.MatchString(l) {
				t.Errorf("a failure path claims success: %q", l)
			}
		}
	}
}

func sha256Of(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
