package main

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func outdatedManifest(name, version string, hosts ...string) *manifest.Manifest {
	return &manifest.Manifest{
		APIVersion: "capm/v0",
		Kind:       "Agent",
		Metadata:   manifest.Metadata{Name: name, Version: version, Description: "d", Authors: []string{"a"}},
		Base:       manifest.Base{Agent: "claude-code", Version: "1.0.0"},
		Interface:  manifest.Interface{Type: "tty"},
		Model:      manifest.Model{API: "openai-compatible", Requires: manifest.ModelRequires{ToolCalling: true, MinContextTokens: 32000}},
		Permissions: manifest.Permissions{
			Egress: hosts,
			Mounts: []manifest.Mount{{Path: "./workspace", Mode: "read-only"}},
		},
	}
}

type outdatedReg struct {
	srv *httptest.Server
	// latest maps "owner/name" to the resolve response (status 200) or a
	// status code with an error body.
	latest   map[string]outdatedLatest
	manifest map[string]*manifest.Manifest // "owner/name@version"
	mu       sync.Mutex
	paths    []string
	methods  []string
}

type outdatedLatest struct {
	status  int // 0 = 200
	version string
	ownerID int64
	reason  string
}

func newOutdatedReg(t *testing.T) *outdatedReg {
	t.Helper()
	r := &outdatedReg{latest: map[string]outdatedLatest{}, manifest: map[string]*manifest.Manifest{}}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.paths = append(r.paths, req.URL.Path)
		r.methods = append(r.methods, req.Method)
		r.mu.Unlock()
		parts := strings.Split(strings.TrimPrefix(req.URL.Path, "/v1/bundles/"), "/")
		if len(parts) == 3 && parts[2] == "resolve" {
			l, ok := r.latest[parts[0]+"/"+parts[1]]
			switch {
			case !ok || l.status == 404:
				w.WriteHeader(404)
				fmt.Fprint(w, `{"error":"not found"}`)
			case l.status == 410:
				w.WriteHeader(410)
				json.NewEncoder(w).Encode(map[string]string{"error": "removed", "reason": l.reason})
			case l.status != 0:
				w.WriteHeader(l.status)
				fmt.Fprint(w, `{"error":"boom"}`)
			default:
				json.NewEncoder(w).Encode(map[string]any{"version": l.version, "digest": "sha256:" + strings.Repeat("a", 64), "ownerId": l.ownerID})
			}
			return
		}
		if len(parts) == 3 {
			m, ok := r.manifest[parts[0]+"/"+parts[1]+"@"+parts[2]]
			if !ok {
				w.WriteHeader(500)
				fmt.Fprint(w, `{"error":"no manifest"}`)
				return
			}
			json.NewEncoder(w).Encode(map[string]any{"version": parts[2], "digest": "sha256:" + strings.Repeat("a", 64), "manifest": m, "createdAt": time.Now()})
			return
		}
		w.WriteHeader(404)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

type outdatedHarness struct {
	reg *outdatedReg
	e   env
}

func newOutdatedHarness(t *testing.T) *outdatedHarness {
	reg := newOutdatedReg(t)
	return &outdatedHarness{reg: reg, e: env{registry: reg.srv.URL, credDir: filepath.Join(t.TempDir(), "capm")}}
}

// ran records a previous run in known.json.
func (h *outdatedHarness) ran(t *testing.T, owner, name, version string, ownerID int64, m *manifest.Manifest) {
	t.Helper()
	ks := newKnownStore(h.e, &bytes.Buffer{})
	err := ks.update(h.e.registry, owner, name, func(r *knownRecord) {
		r.OwnerID = ownerID
		r.LastRun = &lastRun{Version: version, Digest: "sha256:" + strings.Repeat("a", 64), Manifest: m, At: time.Now()}
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (h *outdatedHarness) run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := runEnv(args, &out, &errb, h.e)
	return code, out.String(), errb.String()
}

func TestOutdatedNothingRecorded(t *testing.T) {
	h := newOutdatedHarness(t)
	code, out, _ := h.run("outdated")
	if code != 0 || !strings.Contains(out, "nothing recorded yet; capm outdated lists bundles you have run") {
		t.Fatalf("exit %d out %q", code, out)
	}
	if len(h.reg.paths) != 0 {
		t.Fatal("made requests with nothing recorded")
	}
}

func TestOutdatedIgnoresOtherRegistriesAndNeverRun(t *testing.T) {
	h := newOutdatedHarness(t)
	ks := newKnownStore(h.e, &bytes.Buffer{})
	ks.update("https://other.example", "bob", "x", func(r *knownRecord) { r.LastRun = &lastRun{Version: "1.0.0"} })
	ks.update(h.e.registry, "bob", "pulled-only", func(r *knownRecord) { r.OwnerID = 5 })
	code, out, _ := h.run("outdated")
	if code != 0 || !strings.Contains(out, "nothing recorded yet") || len(h.reg.paths) != 0 {
		t.Fatalf("exit %d out %q paths %v", code, out, h.reg.paths)
	}
}

func TestOutdatedAllCurrent(t *testing.T) {
	h := newOutdatedHarness(t)
	for _, n := range []string{"a", "b"} {
		h.ran(t, "alice", n, "1.0.0", 7, outdatedManifest(n, "1.0.0", "x.example.com"))
		h.reg.latest["alice/"+n] = outdatedLatest{version: "1.0.0", ownerID: 7}
	}
	code, out, _ := h.run("outdated")
	if code != 0 || strings.TrimSpace(out) != "all 2 bundles are up to date" {
		t.Fatalf("exit %d out %q", code, out)
	}
}

func TestOutdatedTableAndSummaries(t *testing.T) {
	h := newOutdatedHarness(t)
	h.ran(t, "alice", "grow", "1.0.0", 7, outdatedManifest("grow", "1.0.0", "a.example.com"))
	h.reg.latest["alice/grow"] = outdatedLatest{version: "1.1.0", ownerID: 7}
	h.reg.manifest["alice/grow@1.1.0"] = outdatedManifest("grow", "1.1.0", "a.example.com", "b.example.com", "c.example.com")
	h.ran(t, "alice", "same", "1.0.0", 7, outdatedManifest("same", "1.0.0", "a.example.com"))
	h.reg.latest["alice/same"] = outdatedLatest{version: "1.0.1", ownerID: 7}
	h.reg.manifest["alice/same@1.0.1"] = outdatedManifest("same", "1.0.1", "a.example.com")
	h.ran(t, "alice", "current", "2.0.0", 7, outdatedManifest("current", "2.0.0"))
	h.reg.latest["alice/current"] = outdatedLatest{version: "2.0.0", ownerID: 7}

	known := filepath.Join(h.e.credDir, "known.json")
	before, _ := os.ReadFile(known)
	code, out, errb := h.run("outdated")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("want header + 2 rows (current bundle omitted):\n%s", out)
	}
	if f := strings.Fields(lines[0]); strings.Join(f, " ") != "owner/name ran latest changes" {
		t.Fatalf("header %q", lines[0])
	}
	if f := strings.Join(strings.Fields(lines[1]), " "); f != "alice/grow 1.0.0 1.1.0 adds 2 egress hosts" {
		t.Fatalf("row %q", f)
	}
	if f := strings.Join(strings.Fields(lines[2]), " "); f != "alice/same 1.0.0 1.0.1 no permission changes" {
		t.Fatalf("row %q", f)
	}
	after, _ := os.ReadFile(known)
	if !bytes.Equal(before, after) {
		t.Fatal("known.json was modified")
	}
	for i, p := range h.reg.paths {
		if h.reg.methods[i] != "GET" || strings.HasSuffix(p, "/download") {
			t.Fatalf("unexpected request %s %s", h.reg.methods[i], p)
		}
	}
}

func TestOutdatedProblemRowsDoNotFailCommand(t *testing.T) {
	h := newOutdatedHarness(t)
	m := outdatedManifest("x", "1.0.0")
	for _, n := range []string{"gone", "removed", "moved", "flaky", "ok"} {
		h.ran(t, "alice", n, "1.0.0", 7, m)
	}
	h.reg.latest["alice/removed"] = outdatedLatest{status: 410, reason: "malware \x1b[31mred"}
	h.reg.latest["alice/moved"] = outdatedLatest{version: "1.1.0", ownerID: 99}
	h.reg.latest["alice/flaky"] = outdatedLatest{status: 500}
	h.reg.latest["alice/ok"] = outdatedLatest{version: "1.1.0", ownerID: 7}
	h.reg.manifest["alice/ok@1.1.0"] = outdatedManifest("ok", "1.1.0")
	// alice/gone has no entry: 404.
	code, out, _ := h.run("outdated")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	rows := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(out), "\n")[1:] {
		f := strings.Fields(l)
		rows[f[0]] = strings.Join(f[1:], " ")
	}
	want := map[string]string{
		"alice/gone":    "no longer in the registry",
		"alice/removed": "removed by the registry",
		"alice/moved":   "owner changed",
		"alice/flaky":   "could not check",
		"alice/ok":      "1.0.0 1.1.0 no permission changes",
	}
	for k, w := range want {
		if !strings.Contains(rows[k], w) {
			t.Errorf("%s: %q lacks %q\n%s", k, rows[k], w, out)
		}
	}
	if strings.Contains(out, "\x1b") {
		t.Fatalf("escape sequence leaked: %q", out)
	}
}

func TestOutdatedNothingCheckableExits1(t *testing.T) {
	h := newOutdatedHarness(t)
	h.ran(t, "alice", "a", "1.0.0", 7, outdatedManifest("a", "1.0.0"))
	h.reg.srv.Close()
	code, _, errb := h.run("outdated")
	if code != 1 || !strings.Contains(errb, "could not check") {
		t.Fatalf("exit %d err %q", code, errb)
	}
}

func TestOutdatedMetadataFailureIsARow(t *testing.T) {
	h := newOutdatedHarness(t)
	h.ran(t, "alice", "a", "1.0.0", 7, outdatedManifest("a", "1.0.0"))
	h.reg.latest["alice/a"] = outdatedLatest{version: "1.1.0", ownerID: 7} // no manifest: 500
	code, out, _ := h.run("outdated")
	if code != 0 || !strings.Contains(out, "alice/a") || !strings.Contains(out, "1.1.0") || !strings.Contains(out, "could not fetch") {
		t.Fatalf("exit %d out %q", code, out)
	}
}

func TestOutdatedInvalidRegistryManifestIsARow(t *testing.T) {
	h := newOutdatedHarness(t)
	h.ran(t, "alice", "a", "1.0.0", 7, outdatedManifest("a", "1.0.0"))
	h.reg.latest["alice/a"] = outdatedLatest{version: "1.1.0", ownerID: 7}
	bad := outdatedManifest("a", "1.1.0")
	bad.Permissions.Egress = []string{"not a host!"}
	h.reg.manifest["alice/a@1.1.0"] = bad
	code, out, _ := h.run("outdated")
	if code != 0 || !strings.Contains(out, "invalid manifest") {
		t.Fatalf("exit %d out %q", code, out)
	}
}

func TestOutdatedNoRecordedManifest(t *testing.T) {
	h := newOutdatedHarness(t)
	h.ran(t, "alice", "a", "1.0.0", 7, nil)
	h.reg.latest["alice/a"] = outdatedLatest{version: "1.1.0", ownerID: 7}
	h.reg.manifest["alice/a@1.1.0"] = outdatedManifest("a", "1.1.0")
	code, out, _ := h.run("outdated")
	if code != 0 || !strings.Contains(out, "unknown (no manifest recorded)") {
		t.Fatalf("exit %d out %q", code, out)
	}
}

func TestOutdatedUsage(t *testing.T) {
	h := newOutdatedHarness(t)
	if code, _, errb := h.run("outdated", "extra"); code != 2 || !strings.Contains(errb, "usage: capm outdated") {
		t.Fatalf("exit %d %q", code, errb)
	}
}
