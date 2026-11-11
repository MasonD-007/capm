package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/MasonD-007/capm/manifest"
)

type metadataResp struct {
	Version   string            `json:"version"`
	Digest    string            `json:"digest"`
	Yanked    bool              `json:"yanked"`
	Manifest  manifest.Manifest `json:"manifest"`
	Summary   manifest.Summary  `json:"summary"`
	CreatedAt time.Time         `json:"createdAt"`
	Error     string            `json:"error"`
}

func (e *env) metadata(t *testing.T, path string) (int, metadataResp) {
	t.Helper()
	c, b := e.do(t, "GET", path, nil)
	var m metadataResp
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v: %s", path, err, b)
	}
	return c, m
}

func TestMetadataReturnsManifestSummaryAndDigest(t *testing.T) {
	e, _ := setupCfg(t, Config{})
	tbs := publishVersions(t, e, "1.0.0", "1.1.0")
	e.user.ok = false // reads need no credentials

	c, m := e.metadata(t, "/v1/bundles/alice/x/1.0.0")
	if c != 200 {
		t.Fatalf("status %d: %+v", c, m)
	}
	if m.Version != "1.0.0" || m.Manifest.Metadata.Version != "1.0.0" || m.Manifest.Metadata.Name != "x" {
		t.Errorf("wrong version selected: %+v", m)
	}
	sum := sha256.Sum256(tbs["1.0.0"])
	if want := "sha256:" + hex.EncodeToString(sum[:]); m.Digest != want {
		t.Errorf("digest %q, want %q", m.Digest, want)
	}
	if m.Yanked {
		t.Error("not yanked")
	}
	if m.CreatedAt.IsZero() {
		t.Error("createdAt missing")
	}
	// The summary is the one EnforcedSummary derives from the stored manifest.
	if len(m.Summary.Egress) != 1 || m.Summary.Egress[0] != "api.github.com" {
		t.Errorf("summary egress %v", m.Summary.Egress)
	}
	if got := m.Summary.NoticeTexts(manifest.NoticeNetwork); len(got) != 1 || got[0] != manifest.EgressEnforcementNotice {
		t.Errorf("network notices %v", got)
	}

	// The other version comes back with its own manifest and digest.
	c, m2 := e.metadata(t, "/v1/bundles/alice/x/1.1.0")
	if c != 200 || m2.Manifest.Metadata.Version != "1.1.0" || m2.Digest == m.Digest {
		t.Errorf("1.1.0: %d %+v", c, m2)
	}
}

// The digest in the metadata is the digest of what /download serves.
func TestMetadataDigestMatchesDownload(t *testing.T) {
	e, _ := setupCfg(t, Config{})
	publishVersions(t, e, "1.0.0")
	_, m := e.metadata(t, "/v1/bundles/alice/x/1.0.0")
	c, body := e.do(t, "GET", "/v1/bundles/alice/x/1.0.0/download", nil)
	if c != 200 {
		t.Fatalf("download %d", c)
	}
	sum := sha256.Sum256(body)
	if want := "sha256:" + hex.EncodeToString(sum[:]); m.Digest != want {
		t.Errorf("metadata digest %q, download hashes to %q", m.Digest, want)
	}
}

func TestMetadataNotFound(t *testing.T) {
	e, _ := setupCfg(t, Config{})
	publishVersions(t, e, "1.0.0")
	for _, tc := range []struct{ path, msg string }{
		{"/v1/bundles/nobody/x/1.0.0", "bundle not found"},
		{"/v1/bundles/alice/nope/1.0.0", "bundle not found"},
		{"/v1/bundles/alice/x/9.9.9", "version not found"},
		// Only exact versions are accepted here; callers resolve "latest" first.
		{"/v1/bundles/alice/x/latest", "version not found"},
	} {
		c, m := e.metadata(t, tc.path)
		if c != 404 || m.Error != tc.msg {
			t.Errorf("%s: %d %q, want 404 %q", tc.path, c, m.Error, tc.msg)
		}
	}
}

// A yanked version is still reported (exact pins keep working) and is marked.
func TestMetadataYankedVersionStillReturned(t *testing.T) {
	e, _ := setupCfg(t, Config{})
	publishVersions(t, e, "1.0.0", "1.1.0")
	if c, b := e.do(t, "POST", "/v1/bundles/alice/x/1.1.0/yank", nil); c != 200 {
		t.Fatalf("yank %d %s", c, b)
	}
	c, m := e.metadata(t, "/v1/bundles/alice/x/1.1.0")
	if c != 200 || !m.Yanked || m.Version != "1.1.0" {
		t.Errorf("%d %+v", c, m)
	}
	if _, m0 := e.metadata(t, "/v1/bundles/alice/x/1.0.0"); m0.Yanked {
		t.Error("1.0.0 must not be marked yanked")
	}
}

// The new {version} route overlaps /resolve; the literal route must still win.
func TestMetadataRouteDoesNotShadowResolve(t *testing.T) {
	e, _ := setupCfg(t, Config{})
	publishVersions(t, e, "1.0.0")
	c, r := e.resolve(t, "latest")
	if c != 200 || r.Version != "1.0.0" {
		t.Fatalf("resolve: %d %+v", c, r)
	}
}

func TestMetadataTildeOwner404(t *testing.T) {
	e, _ := setupCfg(t, Config{})
	publishVersions(t, e, "1.0.0")
	e.user.id = 2 // alice's login moves to id 2; id 1 is tombstoned as "~1"
	e.do(t, "PUT", "/v1/bundles/alice/x/2.0.0", bundle(t, "x", "2.0.0"))
	for _, p := range []string{"/v1/bundles/~1/x/1.0.0", "/v1/bundles/%7E1/x/1.0.0"} {
		if c, b := e.do(t, "GET", p, nil); c != 404 || bytes.Contains(b, []byte(`"manifest"`)) {
			t.Errorf("%s: %d %s", p, c, b)
		}
	}
}
