package api

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/MasonD-007/capm/manifest"
)

func bundleWithReadme(t *testing.T, name, version, readme string) []byte {
	t.Helper()
	dir := t.TempDir()
	y := "apiVersion: capm/v0\nkind: Agent\nmetadata: {name: " + name + ", version: " + version + "}\n" +
		"base: {agent: claude-code, version: 2.1.292}\ninterface: {type: tty}\n" +
		"model: {api: openai-compatible, requires: {toolCalling: true, minContextTokens: 1000}}\n"
	os.WriteFile(filepath.Join(dir, manifest.FileName), []byte(y), 0o644)
	os.WriteFile(filepath.Join(dir, "README.md"), []byte(readme), 0o644)
	b, err := manifest.PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMetadataIncludesReadme(t *testing.T) {
	e := setup(t)
	const rm = "# Hello\n\nUNIQUE-README-MARKER\n"
	if c, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", bundleWithReadme(t, "x", "1.0.0", rm)); c != 201 {
		t.Fatalf("%d %s", c, b)
	}
	if c, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.1.0", bundle(t, "x", "1.1.0")); c != 201 {
		t.Fatalf("%d %s", c, b)
	}
	c, b := e.do(t, "GET", "/v1/bundles/alice/x/1.0.0", nil)
	if c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	var m struct {
		Readme string `json:"readme"`
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(b, &m); err != nil || m.Readme != rm || m.Digest == "" {
		t.Fatalf("%+v %v %s", m, err, b)
	}
	// No README: the field is absent or empty, and everything else is there.
	c, b = e.do(t, "GET", "/v1/bundles/alice/x/1.1.0", nil)
	if c != 200 {
		t.Fatalf("%d %s", c, b)
	}
	var raw map[string]any
	json.Unmarshal(b, &raw)
	if v, ok := raw["readme"]; ok && v != "" {
		t.Fatalf("readme = %v, want absent or empty", v)
	}
	for _, k := range []string{"ownerId", "version", "digest", "yanked", "manifest", "summary", "riskLabels", "createdAt"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("metadata lost field %q", k)
		}
	}
}

func TestReadmeBodyNotInVersionsOrList(t *testing.T) {
	e := setup(t)
	if c, b := e.do(t, "PUT", "/v1/bundles/alice/x/1.0.0", bundleWithReadme(t, "x", "1.0.0", "UNIQUE-README-MARKER")); c != 201 {
		t.Fatalf("%d %s", c, b)
	}
	for _, p := range []string{"/v1/bundles/alice/x", "/v1/bundles", "/v1/bundles?q=x", "/v1/bundles/alice/x/resolve"} {
		c, b := e.do(t, "GET", p, nil)
		if c != 200 {
			t.Fatalf("%s: %d %s", p, c, b)
		}
		if bytes.Contains(b, []byte("UNIQUE-README-MARKER")) || bytes.Contains(b, []byte(`"readme"`)) {
			t.Errorf("%s leaks README: %s", p, b)
		}
	}
}
