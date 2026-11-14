package sigverify

import (
	"bytes"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// The real Actions fixture is a DSSE/in-toto attestation (the only public
// Actions bundle in sigstore-go's own test data) whose subject digest is
// SHA-512, not the message signature capm will use. Tests that need the real
// fixture therefore use attestationProfile; production Verify refuses it (see
// TestProductionRejectsFixture). Everything else about the verifier is the
// production code path.
var attestationProfile = profile{
	alg:        "sha512",
	digestLen:  64,
	versions:   []string{"v0.1", "v0.2", "v0.3"},
	allowDSSE:  true,
	requireSCT: true,
}

const (
	fixtureActions   = "sigstore.js@2.0.0-provenance.sigstore.json"
	fixtureTwoSigs   = "dsse-2sigs.sigstore.json"
	fixturePublicKey = "public-key-validity.sigstore.json"

	// subject digest of the in-toto statement in fixtureActions (pkg:npm/sigstore@2.0.0)
	fixtureDigestHex = "46d4e2f74c4877316640000a6fdf8a8b59f1e0847667973e9859f774dd31b8f1e0937813b777fb66a2ac67d50540fe34640966eee9fc2ccca387082b4c85cd3c"
)

func readFixture(t testing.TB, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func fixtureDigest(t testing.TB) []byte {
	t.Helper()
	d := mustHex(t, fixtureDigestHex)
	if len(d) != sha512.Size {
		t.Fatal("bad fixture digest")
	}
	return d
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b := make([]byte, len(s)/2)
	for i := range b {
		var v byte
		for _, c := range []byte(s[2*i : 2*i+2]) {
			v <<= 4
			switch {
			case c >= '0' && c <= '9':
				v |= c - '0'
			case c >= 'a' && c <= 'f':
				v |= c - 'a' + 10
			default:
				t.Fatalf("bad hex %q", s)
			}
		}
		b[i] = v
	}
	return b
}

func embeddedTrustedRoot(t testing.TB) *root.TrustedRoot {
	t.Helper()
	tr, err := embeddedRoot()
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

// realVerifier verifies the Actions fixture against the embedded root.
func realVerifier(t testing.TB) *verifier {
	return &verifier{tr: embeddedTrustedRoot(t), now: time.Now, profile: attestationProfile, policy: checkIdentity}
}

// actionsExpect is what the fixture's certificate actually says.
func actionsExpect() Expect {
	return Expect{OwnerLogin: "sigstore"}
}

// mutate decodes bundle JSON, applies f, and re-encodes it.
func mutate(t testing.TB, raw []byte, f func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	f(m)
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// path navigates nested maps and slices: path(m, "a", 0, "b").
func path(t testing.TB, v any, keys ...any) any {
	t.Helper()
	for _, k := range keys {
		switch kk := k.(type) {
		case string:
			m, ok := v.(map[string]any)
			if !ok {
				t.Fatalf("path %v: not an object at %q", keys, kk)
			}
			v, ok = m[kk]
			if !ok {
				t.Fatalf("path %v: missing %q", keys, kk)
			}
		case int:
			s, ok := v.([]any)
			if !ok || kk >= len(s) {
				t.Fatalf("path %v: not a list at %d", keys, kk)
			}
			v = s[kk]
		}
	}
	return v
}

// setPath sets the value at keys (the last key names the field to set).
func setPath(t testing.TB, root any, val any, keys ...any) {
	t.Helper()
	parent := path(t, root, keys[:len(keys)-1]...)
	switch last := keys[len(keys)-1].(type) {
	case string:
		parent.(map[string]any)[last] = val
	case int:
		parent.([]any)[last] = val
	}
}

// flipBase64 flips one bit in the middle of the base64 string at keys.
func flipBase64(t testing.TB, m map[string]any, keys ...any) {
	t.Helper()
	s := path(t, m, keys...).(string)
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)/2] ^= 0x01
	setPath(t, m, base64.StdEncoding.EncodeToString(b), keys...)
}

func mustMarshalRoot(t testing.TB, mutateRoot func(m map[string]any)) *root.TrustedRoot {
	t.Helper()
	raw := mutate(t, embeddedRootJSON, mutateRoot)
	tr, err := root.NewTrustedRootFromJSON(raw)
	if err != nil {
		t.Fatalf("mutated root does not parse: %v", err)
	}
	return tr
}

func fulcioCAs(t testing.TB) []*root.FulcioCertificateAuthority {
	t.Helper()
	var out []*root.FulcioCertificateAuthority
	for _, c := range embeddedTrustedRoot(t).FulcioCertificateAuthorities() {
		f, ok := c.(*root.FulcioCertificateAuthority)
		if !ok {
			t.Fatalf("unexpected CA type %T", c)
		}
		out = append(out, f)
	}
	return out
}

func sameBytes(a, b []byte) bool { return bytes.Equal(a, b) }
