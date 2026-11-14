package sigverify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"go/parser"
	"go/token"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestEmbeddedRootIsCurrent(t *testing.T) {
	tr := embeddedTrustedRoot(t)
	now := time.Now()

	var cas int
	for _, ca := range fulcioCAs(t) {
		if validAt(ca.ValidityPeriodStart, ca.ValidityPeriodEnd, now) {
			cas++
		}
	}
	if cas < 1 {
		t.Errorf("no Fulcio CA is valid now (%v): refresh with scripts/update-trusted-root.sh", now)
	}
	var logs int
	for _, l := range tr.RekorLogs() {
		if validAt(l.ValidityPeriodStart, l.ValidityPeriodEnd, now) {
			logs++
		}
	}
	if logs < 1 {
		t.Errorf("no Rekor log is valid now")
	}
	var cts int
	for _, l := range tr.CTLogs() {
		if validAt(l.ValidityPeriodStart, l.ValidityPeriodEnd, now) {
			cts++
		}
	}
	if cts < 1 {
		t.Errorf("no CT log is valid now")
	}
	t.Logf("valid now: %d Fulcio CA(s), %d Rekor log(s), %d CT log(s)", cas, logs, cts)

	// The first trust decision of a real run must not depend on anything but
	// these bytes: parsing twice yields the same cached value.
	a, _ := embeddedRoot()
	b, _ := embeddedRoot()
	if a != b {
		t.Error("embedded root is not parsed once")
	}
}

func TestTrustedRootProvenanceMatchesFile(t *testing.T) {
	sum := sha256.Sum256(embeddedRootJSON)
	want := hex.EncodeToString(sum[:])
	md, err := os.ReadFile("TRUSTED_ROOT.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^- sha256: ([0-9a-f]{64})$`).FindSubmatch(md)
	if m == nil {
		t.Fatal("TRUSTED_ROOT.md has no '- sha256:' line")
	}
	if string(m[1]) != want {
		t.Errorf("TRUSTED_ROOT.md records sha256 %s but trusted_root.json is %s; run scripts/update-trusted-root.sh or fix the record", m[1], want)
	}
	if !regexp.MustCompile(`(?m)^- retrieved: \d{4}-\d{2}-\d{2}$`).Match(md) {
		t.Error("TRUSTED_ROOT.md has no '- retrieved: YYYY-MM-DD' line")
	}
}

// ---- offline ------------------------------------------------------------------

type noNetwork struct{ hits atomic.Int32 }

func (n *noNetwork) RoundTrip(*http.Request) (*http.Response, error) {
	n.hits.Add(1)
	return nil, errors.New("sigverify test: network access attempted")
}

// Verification must never touch the network. Every path that could dial is
// replaced with one that records the attempt: the default HTTP transport and
// client, and the default resolver (which every net.Dial of a name goes
// through). A raw IP dial would bypass the resolver, so the package's own
// source is also checked to import no network or process packages
// (TestNoNetworkImports) and the dependency inventory is in the README.
func TestVerifyIsOffline(t *testing.T) {
	nn := &noNetwork{}
	oldT, oldC, oldR := http.DefaultTransport, http.DefaultClient, net.DefaultResolver
	http.DefaultTransport = nn
	http.DefaultClient = &http.Client{Transport: nn}
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			nn.hits.Add(1)
			return nil, errors.New("sigverify test: DNS attempted")
		},
	}
	t.Cleanup(func() { http.DefaultTransport, http.DefaultClient, net.DefaultResolver = oldT, oldC, oldR })

	raw, d := readFixture(t, fixtureActions), fixtureDigest(t)
	v := realVerifier(t)
	// success, identity failure, crypto failure, staleness, malformed, via the real entry point
	if _, err := v.verifyBytes(raw, d, actionsExpect()); err != nil {
		t.Fatal(err)
	}
	_, _ = v.verifyBytes(raw, d, Expect{OwnerLogin: "evil"})
	bad := append([]byte(nil), d...)
	bad[0] ^= 1
	_, _ = v.verifyBytes(raw, bad, actionsExpect())
	v2 := realVerifier(t)
	v2.tr = mustMarshalRoot(t, func(m map[string]any) { setPath(t, m, []any{}, "tlogs") })
	_, _ = v2.verifyBytes(raw, d, actionsExpect())
	_, _ = Verify(raw, make([]byte, 32), actionsExpect())
	_, _ = Verify([]byte("garbage"), make([]byte, 32), actionsExpect())
	if n := nn.hits.Load(); n != 0 {
		t.Fatalf("%d network attempts during verification", n)
	}

	// control: the guard really does catch an attempt
	_, _ = http.Get("http://127.0.0.1:1/")
	if nn.hits.Load() != 1 {
		t.Fatal("test guard did not observe a deliberate request")
	}
}

func TestNoNetworkImports(t *testing.T) {
	forbidden := map[string]bool{
		"net": true, "net/http": true, "net/url": false, "os/exec": true, "os": true,
		"io/ioutil": true, "plugin": true, "syscall": true, "unsafe": true,
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if forbidden[p] {
				t.Errorf("%s imports %q: sigverify must stay free of I/O", f, p)
			}
		}
	}
}
