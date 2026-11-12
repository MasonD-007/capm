package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MasonD-007/capm/manifest"
)

const secretToken = "s3cret-token-value"

type fakeVersion struct {
	tar    []byte
	yanked bool
}

// manifestOf reads the manifest from the first entry of a bundle tarball
// without unpacking the rest (hostile test tarballs carry bad entries after it).
func manifestOf(tb []byte) (*manifest.Manifest, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tb))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	if _, err := tr.Next(); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(tr)
	if err != nil {
		return nil, err
	}
	return manifest.Parse(data)
}

// fakeRegistry is an httptest stand-in for the capm backend.
type fakeRegistry struct {
	srv *httptest.Server
	mu  sync.Mutex

	versions map[string]*fakeVersion // key "owner/name@version"
	order    map[string][]string     // owner/name -> versions

	pushBody []byte
	pushAuth string
	pushPath string
	pushCode int // override publish status when non-zero
	pushMsg  string
	// pushLimit, when set, is sent as the "limit" field of the error (quota rejections).
	pushLimit string

	userCode, verifyURI string // override device-flow fields
	digest, meLogin     string
	literalDigest       bool   // send digest as is, even when empty
	forceVersion        string // override the version resolve reports
	metaManifest        any    // override the manifest the metadata endpoint reports
	metaSummary         any    // override the (untrusted) summary the metadata endpoint reports
	metaRiskLabels      any    // if set, the (untrusted) riskLabels the metadata endpoint reports
	metaVersion         string // override the version the metadata endpoint reports
	downloads           int    // number of /download calls
	ownerID             int64  // owner id sent by resolve and metadata; 0 = omitted (an older server)

	polls int // number of /auth/token calls
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	f := &fakeRegistry{versions: map[string]*fakeVersion{}, order: map[string][]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/device", func(w http.ResponseWriter, r *http.Request) {
		uc, vu := "ABCD-1234", "https://example.test/device"
		if f.userCode != "" {
			uc, vu = f.userCode, f.verifyURI
		}
		json.NewEncoder(w).Encode(map[string]any{"device_code": "dc", "user_code": uc, "verification_uri": vu, "interval": 1, "expires_in": 900})
	})
	mux.HandleFunc("POST /v1/auth/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.polls++
		n := f.polls
		f.mu.Unlock()
		if n < 3 {
			w.WriteHeader(428)
			io.WriteString(w, `{"error":"authorization_pending"}`)
			return
		}
		io.WriteString(w, `{"token":"`+secretToken+`"}`)
	})
	mux.HandleFunc("GET /v1/auth/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+secretToken {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":"authentication required"}`)
			return
		}
		l := "alice"
		if f.meLogin != "" {
			l = f.meLogin
		}
		json.NewEncoder(w).Encode(map[string]any{"id": 7, "login": l})
	})
	mux.HandleFunc("PUT /v1/bundles/{owner}/{name}/{version}", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.pushBody, f.pushAuth, f.pushPath = b, r.Header.Get("Authorization"), r.URL.Path
		code := f.pushCode
		f.mu.Unlock()
		if code != 0 {
			w.WriteHeader(code)
			msg := f.pushMsg
			if msg == "" {
				msg = "version already exists"
			}
			body := map[string]string{"error": msg}
			if f.pushLimit != "" {
				body["limit"] = f.pushLimit
			}
			json.NewEncoder(w).Encode(body)
			return
		}
		w.WriteHeader(201)
		io.WriteString(w, `{}`)
	})
	mux.HandleFunc("GET /v1/bundles/{owner}/{name}/resolve", func(w http.ResponseWriter, r *http.Request) {
		o, n := r.PathValue("owner"), r.PathValue("name")
		rng := r.URL.Query().Get("range")
		f.mu.Lock()
		defer f.mu.Unlock()
		var pick string
		if rng == "latest" || rng == "" {
			for _, v := range f.order[o+"/"+n] { // later entries are newer
				if !f.versions[o+"/"+n+"@"+v].yanked {
					pick = v
				}
			}
		} else if _, ok := f.versions[o+"/"+n+"@"+rng]; ok {
			pick = rng
		}
		if pick == "" {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":"version not found"}`)
			return
		}
		fv := f.versions[o+"/"+n+"@"+pick]
		digest := f.digest
		if digest == "" && !f.literalDigest {
			sum := sha256.Sum256(fv.tar)
			digest = "sha256:" + hex.EncodeToString(sum[:])
		}
		out := map[string]any{"version": pick, "digest": digest, "yanked": fv.yanked}
		if fv.yanked {
			out["warning"] = "yanked"
		}
		if f.forceVersion != "" {
			out["version"] = f.forceVersion
		}
		if f.ownerID != 0 {
			out["ownerId"] = f.ownerID
		}
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /v1/bundles/{owner}/{name}/{version}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		k := r.PathValue("owner") + "/" + r.PathValue("name") + "@" + r.PathValue("version")
		fv := f.versions[k]
		if fv == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":"version not found"}`)
			return
		}
		m, err := manifestOf(fv.tar)
		if err != nil {
			w.WriteHeader(500)
			return
		}
		sum := sha256.Sum256(fv.tar)
		out := map[string]any{"version": r.PathValue("version"), "digest": "sha256:" + hex.EncodeToString(sum[:]),
			"yanked": fv.yanked, "manifest": m, "summary": m.EnforcedSummary(), "createdAt": time.Now()}
		if f.ownerID != 0 {
			out["ownerId"] = f.ownerID
		}
		if f.metaManifest != nil {
			out["manifest"] = f.metaManifest
		}
		if f.metaSummary != nil {
			out["summary"] = f.metaSummary
		}
		if f.metaRiskLabels != nil {
			out["riskLabels"] = f.metaRiskLabels
		}
		if f.metaVersion != "" {
			out["version"] = f.metaVersion
		}
		json.NewEncoder(w).Encode(out)
	})
	mux.HandleFunc("GET /v1/bundles/{owner}/{name}/{version}/download", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.downloads++
		fv := f.versions[r.PathValue("owner")+"/"+r.PathValue("name")+"@"+r.PathValue("version")]
		f.mu.Unlock()
		if fv == nil {
			w.WriteHeader(404)
			io.WriteString(w, `{"error":"version not found"}`)
			return
		}
		w.Write(fv.tar)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRegistry) add(owner, name, version string, tar []byte, yanked bool) {
	k := owner + "/" + name
	f.versions[k+"@"+version] = &fakeVersion{tar, yanked}
	f.order[k] = append(f.order[k], version)
}

func testBundleDir(t *testing.T, name, version string) string {
	t.Helper()
	dir := t.TempDir()
	y := "apiVersion: capm/v0\nkind: Agent\nmetadata: {name: " + name + ", version: " + version + "}\n" +
		"base: {agent: claude-code, version: 2.1.292}\ninterface: {type: tty}\n" +
		"model: {api: openai-compatible, requires: {toolCalling: true, minContextTokens: 1000}}\n" +
		"permissions: {egress: [api.github.com]}\n"
	if err := os.WriteFile(filepath.Join(dir, manifest.FileName), []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func testBundleTar(t *testing.T, name, version string) []byte {
	t.Helper()
	b, err := manifest.PackDir(testBundleDir(t, name, version))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type harness struct {
	reg  *fakeRegistry
	env  env
	out  bytes.Buffer
	errb bytes.Buffer
}

func newHarness(t *testing.T) *harness {
	reg := newFakeRegistry(t)
	h := &harness{reg: reg}
	h.env = env{registry: reg.srv.URL, credDir: filepath.Join(t.TempDir(), "capm"),
		sleep: func(time.Duration) {}}
	return h
}

func (h *harness) run(args ...string) int {
	h.out.Reset()
	h.errb.Reset()
	return runEnv(args, &h.out, &h.errb, h.env)
}

func (h *harness) mustLogin(t *testing.T) {
	t.Helper()
	if code := h.run("login"); code != 0 {
		t.Fatalf("login exit %d: %s", code, h.errb.String())
	}
}

func noSecret(t *testing.T, h *harness) {
	t.Helper()
	if strings.Contains(h.out.String(), secretToken) || strings.Contains(h.errb.String(), secretToken) {
		t.Fatalf("token leaked:\nstdout=%s\nstderr=%s", h.out.String(), h.errb.String())
	}
}

func TestLoginStoresCredentials0600(t *testing.T) {
	h := newHarness(t)
	h.mustLogin(t)
	s := h.out.String()
	if !strings.Contains(s, "https://example.test/device") || !strings.Contains(s, "ABCD-1234") {
		t.Errorf("login output lacks url/code: %q", s)
	}
	noSecret(t, h)
	p := filepath.Join(h.env.credDir, "credentials.json")
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("credentials mode %v", st.Mode().Perm())
	}
	ds, _ := os.Stat(h.env.credDir)
	if ds.Mode().Perm() != 0o700 {
		t.Errorf("credentials dir mode %v", ds.Mode().Perm())
	}
	b, _ := os.ReadFile(p)
	if !strings.Contains(string(b), `"alice"`) || !strings.Contains(string(b), secretToken) {
		t.Errorf("credentials content: %s", b)
	}
}

func TestPushSendsPackedBytesWithBearer(t *testing.T) {
	h := newHarness(t)
	h.mustLogin(t)
	dir := testBundleDir(t, "myagent", "1.2.3")
	want, err := manifest.PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if code := h.run("push", dir); code != 0 {
		t.Fatalf("exit %d: %s", code, h.errb.String())
	}
	if !bytes.Equal(h.reg.pushBody, want) {
		t.Error("pushed bytes differ from PackDir output")
	}
	if h.reg.pushAuth != "Bearer "+secretToken {
		t.Errorf("auth header %q", h.reg.pushAuth)
	}
	if h.reg.pushPath != "/v1/bundles/alice/myagent/1.2.3" {
		t.Errorf("path %q", h.reg.pushPath)
	}
	if !strings.Contains(h.out.String(), "alice/myagent@1.2.3") {
		t.Errorf("stdout %q", h.out.String())
	}
	noSecret(t, h)
}

func TestPushWithoutLogin(t *testing.T) {
	h := newHarness(t)
	if code := h.run("push", testBundleDir(t, "a", "1.0.0")); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.errb.String(), "run capm login") {
		t.Errorf("stderr %q", h.errb.String())
	}
	if h.reg.pushBody != nil {
		t.Error("something was pushed")
	}
}

func TestPushConflictSurfacesServerError(t *testing.T) {
	h := newHarness(t)
	h.mustLogin(t)
	h.reg.pushCode = 409
	if code := h.run("push", testBundleDir(t, "a", "1.0.0")); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(h.errb.String(), "version already exists") {
		t.Errorf("stderr %q", h.errb.String())
	}
	noSecret(t, h)
}

func TestPushUsageAndInvalid(t *testing.T) {
	h := newHarness(t)
	h.mustLogin(t)
	if code := h.run("push"); code != 2 {
		t.Errorf("no args: %d", code)
	}
	bad := t.TempDir()
	os.WriteFile(filepath.Join(bad, "capm.yaml"), []byte("apiVersion: capm/v0\nkind: Agent\n"), 0o644)
	if code := h.run("push", bad); code != 1 {
		t.Errorf("invalid manifest: %d", code)
	}
	if h.reg.pushBody != nil {
		t.Error("invalid bundle pushed")
	}
}

func TestCredentialsIgnoredForOtherRegistry(t *testing.T) {
	h := newHarness(t)
	h.mustLogin(t)
	h.env.registry = "http://127.0.0.1:1"
	if code := h.run("push", testBundleDir(t, "a", "1.0.0")); code != 1 || !strings.Contains(h.errb.String(), "run capm login") {
		t.Fatalf("exit %d stderr %q", code, h.errb.String())
	}
}
