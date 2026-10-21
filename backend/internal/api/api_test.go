package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/MasonD-007/capm/backend/internal/store"
	"github.com/MasonD-007/capm/manifest"
)

func bundle(t *testing.T, name, version string) []byte {
	t.Helper()
	dir := t.TempDir()
	y := "apiVersion: capm/v0\nkind: Agent\nmetadata: {name: " + name + ", version: " + version + "}\n" +
		"base: {agent: claude-code, version: 2.1.292}\ninterface: {type: tty}\n" +
		"model: {api: openai-compatible, requires: {toolCalling: true, minContextTokens: 1000}}\n" +
		"permissions: {egress: [api.github.com]}\n"
	os.WriteFile(filepath.Join(dir, manifest.FileName), []byte(y), 0o644)
	b, err := manifest.PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type env struct {
	srv  *httptest.Server
	dir  string
	user *struct {
		id    int64
		login string
		ok    bool
	}
}

func setup(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	e := &env{dir: dir}
	e.user = &struct {
		id    int64
		login string
		ok    bool
	}{1, "alice", true}
	a := New(s, func(r *http.Request) (int64, string, bool) { return e.user.id, e.user.login, e.user.ok })
	e.srv = httptest.NewServer(a.Handler())
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) do(t *testing.T, method, path string, body []byte) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestRoundTrip(t *testing.T) {
	e := setup(t)
	tb := bundle(t, "pr-reviewer", "0.1.0")
	if c, b := e.do(t, "PUT", "/v1/bundles/alice/pr-reviewer/0.1.0", tb); c != 201 {
		t.Fatalf("%d %s", c, b)
	}
	e.user.ok = false // reads need no credentials
	c, b := e.do(t, "GET", "/v1/bundles/alice/pr-reviewer", nil)
	if c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	var vs []struct {
		Version string
		Digest  string
		Yanked  bool
		Summary manifest.Summary
	}
	if err := json.Unmarshal(b, &vs); err != nil || len(vs) != 1 {
		t.Fatalf("%v %s", err, b)
	}
	if !strings.HasPrefix(vs[0].Digest, "sha256:") || vs[0].Version != "0.1.0" {
		t.Fatalf("%+v", vs[0])
	}
	if len(vs[0].Summary.Egress) != 1 || vs[0].Summary.Egress[0] != "api.github.com" {
		t.Fatalf("summary %+v", vs[0].Summary)
	}
	if !bytes.Contains(b, []byte(`"summary"`)) || !bytes.Contains(b, []byte(`"manifest"`)) {
		t.Fatalf("missing fields: %s", b)
	}
	c, got := e.do(t, "GET", "/v1/bundles/alice/pr-reviewer/0.1.0/download", nil)
	if c != 200 || !bytes.Equal(got, tb) {
		t.Fatalf("download %d", c)
	}
	c, b = e.do(t, "GET", "/v1/bundles", nil)
	if c != 200 || !bytes.Contains(b, []byte(`"alice"`)) {
		t.Fatalf("%d %s", c, b)
	}
}

func TestEmptyListIsArray(t *testing.T) {
	e := setup(t)
	c, b := e.do(t, "GET", "/v1/bundles?limit=5&offset=0", nil)
	if c != 200 || strings.TrimSpace(string(b)) != "[]" {
		t.Fatalf("%d %s", c, b)
	}
	if c, _ := e.do(t, "GET", "/v1/bundles?limit=abc", nil); c != 400 {
		t.Fatalf("limit abc: %d", c)
	}
}

func TestNotFound(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/v1/bundles/a/b", "/v1/bundles/a/b/1.0.0/download"} {
		c, b := e.do(t, "GET", p, nil)
		if c != 404 || !bytes.Contains(b, []byte(`"error"`)) {
			t.Fatalf("%s %d %s", p, c, b)
		}
	}
}

func TestDuplicate409(t *testing.T) {
	e := setup(t)
	tb := bundle(t, "x", "1.0.0")
	e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", tb)
	if c, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", tb); c != 409 {
		t.Fatalf("%d %s", c, b)
	}
}

func TestConcurrentPublish(t *testing.T) {
	e := setup(t)
	tb := bundle(t, "x", "1.0.0")
	var wg sync.WaitGroup
	codes := make(chan int, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("PUT", e.srv.URL+"/v1/bundles/alice/x/1.0.0", bytes.NewReader(tb))
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				codes <- -1
				return
			}
			resp.Body.Close()
			codes <- resp.StatusCode
		}()
	}
	wg.Wait()
	close(codes)
	n201, n409 := 0, 0
	for c := range codes {
		switch c {
		case 201:
			n201++
		case 409:
			n409++
		default:
			t.Errorf("unexpected %d", c)
		}
	}
	if n201 != 1 || n409 != 19 {
		t.Fatalf("201=%d 409=%d", n201, n409)
	}
	ents, _ := os.ReadDir(filepath.Join(e.dir, "blobs"))
	if len(ents) != 1 {
		t.Fatalf("blobs: %d", len(ents))
	}
}

func TestMismatch400(t *testing.T) {
	e := setup(t)
	for _, p := range []string{"/v1/bundles/alice/other/1.0.0", "/v1/bundles/alice/x/2.0.0"} {
		if c, b := e.do(t, "PUT", p, bundle(t, "x", "1.0.0")); c != 400 {
			t.Fatalf("%s %d %s", p, c, b)
		}
	}
}

func TestEvilTarball400(t *testing.T) {
	e := setup(t)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "../evil", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1})
	tw.Write([]byte("x"))
	tw.Close()
	gz.Close()
	if c, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", buf.Bytes()); c != 400 {
		t.Fatalf("%d %s", c, b)
	}
	ents, _ := os.ReadDir(filepath.Join(e.dir, "blobs"))
	if len(ents) != 0 {
		t.Fatalf("blobs: %d", len(ents))
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(e.dir), "evil")); err == nil {
		t.Fatal("evil written")
	}
}

func TestInvalidManifest400(t *testing.T) {
	e := setup(t)
	dir := t.TempDir()
	// Valid to pack is impossible, so build the tar by hand.
	y := "apiVersion: capm/v0\nkind: Agent\nmetadata: {name: x, version: 1.0.0}\nbase: {agent: emacs, version: 1}\ninterface: {type: tty}\nmodel: {api: a, requires: {toolCalling: true, minContextTokens: 1}}\n"
	_ = dir
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "capm.yaml", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(y))})
	tw.Write([]byte(y))
	tw.Close()
	gz.Close()
	c, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", buf.Bytes())
	if c != 400 || !bytes.Contains(b, []byte("base.agent")) {
		t.Fatalf("%d %s", c, b)
	}
}

func TestOwnership403(t *testing.T) {
	e := setup(t)
	if c, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", bundle(t, "x", "1.0.0")); c != 201 {
		t.Fatalf("%d %s", c, b)
	}
	// Different owner ID publishing the same name under their own login.
	e.user.id, e.user.login = 2, "bob"
	if c, b := e.do(t, "PUT", "/v1/bundles/bob/x/1.1.0", bundle(t, "x", "1.1.0")); c != 403 {
		t.Fatalf("name owned: %d %s", c, b)
	}
	// Publishing under someone else's login in the URL.
	if c, b := e.do(t, "PUT", "/v1/bundles/alice/y/1.0.0", bundle(t, "y", "1.0.0")); c != 403 {
		t.Fatalf("url owner: %d %s", c, b)
	}
}

func TestUnauthenticatedPublish401(t *testing.T) {
	e := setup(t)
	e.user.ok = false
	if c, _ := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", bundle(t, "x", "1.0.0")); c != 401 {
		t.Fatalf("%d", c)
	}
}
