package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestOutdatedShowsRegistrysSignedClaim(t *testing.T) {
	signedOf := map[string]any{"alice/s": true, "alice/u": false} // alice/n: field absent
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/bundles/"), "/")
		if len(parts) == 3 && parts[2] == "resolve" {
			json.NewEncoder(w).Encode(map[string]any{"version": "1.1.0", "digest": "sha256:" + strings.Repeat("a", 64), "ownerId": 7})
			return
		}
		if len(parts) == 3 {
			out := map[string]any{"version": parts[2], "digest": "sha256:" + strings.Repeat("a", 64), "createdAt": time.Now(),
				"manifest": outdatedManifest(parts[1], parts[2], "a.example.com")}
			if v, ok := signedOf[parts[0]+"/"+parts[1]]; ok {
				out["signed"] = v
			}
			json.NewEncoder(w).Encode(out)
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()
	e := env{registry: srv.URL, credDir: filepath.Join(t.TempDir(), "capm")}
	ks := newKnownStore(e, &bytes.Buffer{})
	for _, n := range []string{"s", "u", "n"} {
		ks.update(e.registry, "alice", n, func(r *knownRecord) {
			r.OwnerID = 7
			r.LastRun = &lastRun{Version: "1.0.0", Digest: "sha256:" + strings.Repeat("a", 64), Manifest: outdatedManifest(n, "1.0.0", "a.example.com"), At: time.Now()}
		})
	}
	var out, errb bytes.Buffer
	if code := runEnv([]string{"outdated"}, &out, &errb, e); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("output:\n%s", out.String())
	}
	if h := strings.Join(strings.Fields(lines[0]), " "); h != "owner/name ran latest signed (registry's claim) changes" {
		t.Errorf("header %q", h)
	}
	want := map[string]string{
		"alice/n": "alice/n 1.0.0 1.1.0 - no permission changes",
		"alice/s": "alice/s 1.0.0 1.1.0 signed no permission changes",
		"alice/u": "alice/u 1.0.0 1.1.0 unsigned no permission changes",
	}
	for _, l := range lines[1:] {
		f := strings.Join(strings.Fields(l), " ")
		key := strings.Fields(l)[0]
		if f != want[key] {
			t.Errorf("row %q, want %q", f, want[key])
		}
	}
}
