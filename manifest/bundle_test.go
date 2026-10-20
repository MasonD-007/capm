package manifest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixtureYAML = `apiVersion: capm/v0
kind: Agent
metadata: {name: pr-reviewer, version: 0.1.0}
base: {agent: claude-code, version: 2.1.292}
interface: {type: tty}
model: {api: openai-compatible, requires: {toolCalling: true, minContextTokens: 1000}}
context: [docs/readme.md]
`

func writeFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, "docs"), 0o755))
	must(os.WriteFile(filepath.Join(dir, FileName), []byte(fixtureYAML), 0o644))
	must(os.WriteFile(filepath.Join(dir, "docs/readme.md"), []byte("hello"), 0o644))
	must(os.WriteFile(filepath.Join(dir, "undeclared.txt"), []byte("nope"), 0o644))
	return dir
}

type entry struct {
	name     string
	typeflag byte
	body     string
	link     string
}

func buildTar(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: 0o644, Linkname: e.link}
		if e.typeflag == tar.TypeReg {
			h.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typeflag == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestPackUnpackRoundTrip(t *testing.T) {
	src := writeFixture(t)
	data, err := PackDir(src)
	if err != nil {
		t.Fatal(err)
	}
	// Undeclared files must not be packed.
	dest := t.TempDir()
	m, err := UnpackTo(data, dest)
	if err != nil {
		t.Fatal(err)
	}
	if m.Metadata.Name != "pr-reviewer" {
		t.Errorf("name = %q", m.Metadata.Name)
	}
	got, err := os.ReadFile(filepath.Join(dest, "docs/readme.md"))
	if err != nil || string(got) != "hello" {
		t.Fatalf("readme = %q, %v", got, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "undeclared.txt")); err == nil {
		t.Error("undeclared file was packed")
	}
	if _, err := os.Stat(filepath.Join(dest, FileName)); err != nil {
		t.Error("capm.yaml missing")
	}
}

func TestPackDirErrors(t *testing.T) {
	t.Run("missing context file", func(t *testing.T) {
		dir := writeFixture(t)
		os.Remove(filepath.Join(dir, "docs/readme.md"))
		if _, err := PackDir(dir); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("symlink context file", func(t *testing.T) {
		dir := writeFixture(t)
		os.Remove(filepath.Join(dir, "docs/readme.md"))
		outside := filepath.Join(t.TempDir(), "secret")
		os.WriteFile(outside, []byte("s"), 0o644)
		if err := os.Symlink(outside, filepath.Join(dir, "docs/readme.md")); err != nil {
			t.Skip(err)
		}
		_, err := PackDir(dir)
		if err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("symlinked parent dir", func(t *testing.T) {
		dir := writeFixture(t)
		outside := t.TempDir()
		os.WriteFile(filepath.Join(outside, "readme.md"), []byte("s"), 0o644)
		os.RemoveAll(filepath.Join(dir, "docs"))
		if err := os.Symlink(outside, filepath.Join(dir, "docs")); err != nil {
			t.Skip(err)
		}
		if _, err := PackDir(dir); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("directory as context", func(t *testing.T) {
		dir := writeFixture(t)
		os.Remove(filepath.Join(dir, "docs/readme.md"))
		os.Mkdir(filepath.Join(dir, "docs/readme.md"), 0o755)
		if _, err := PackDir(dir); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("invalid manifest", func(t *testing.T) {
		dir := writeFixture(t)
		os.WriteFile(filepath.Join(dir, FileName), []byte("kind: x\n"), 0o644)
		if _, err := PackDir(dir); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestUnpackRejects(t *testing.T) {
	good := entry{name: FileName, typeflag: tar.TypeReg, body: fixtureYAML}
	readme := entry{name: "docs/readme.md", typeflag: tar.TypeReg, body: "hi"}
	tests := []struct {
		name    string
		entries []entry
	}{
		{"dotdot", []entry{good, {name: "../evil", typeflag: tar.TypeReg, body: "x"}}},
		{"dotdot nested", []entry{good, {name: "docs/../../evil", typeflag: tar.TypeReg, body: "x"}}},
		{"absolute", []entry{good, {name: "/abs", typeflag: tar.TypeReg, body: "x"}}},
		{"symlink", []entry{good, {name: "docs/readme.md", typeflag: tar.TypeSymlink, link: "/etc/passwd"}}},
		{"hardlink", []entry{good, {name: "docs/readme.md", typeflag: tar.TypeLink, link: "capm.yaml"}}},
		{"directory", []entry{good, {name: "docs/", typeflag: tar.TypeDir}}},
		{"undeclared file", []entry{good, readme, {name: "extra.txt", typeflag: tar.TypeReg, body: "x"}}},
		{"duplicate", []entry{good, readme, readme}},
		{"no manifest", []entry{readme}},
		{"invalid manifest", []entry{{name: FileName, typeflag: tar.TypeReg, body: "kind: x\n"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := t.TempDir()
			if _, err := UnpackTo(buildTar(t, tt.entries...), dest); err == nil {
				t.Fatal("expected error")
			}
			if ents, _ := os.ReadDir(dest); len(ents) != 0 {
				t.Errorf("rejected tarball left files in dest: %v", ents)
			}
		})
	}
	t.Run("not gzip", func(t *testing.T) {
		if _, err := UnpackTo([]byte("junk"), t.TempDir()); err == nil {
			t.Fatal("expected error")
		}
	})
}

func manifestWithContext(n int) string {
	var sb strings.Builder
	sb.WriteString(strings.Split(fixtureYAML, "context:")[0] + "context:\n")
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "  - f%d\n", i)
	}
	return sb.String()
}

func TestUnpackCaps(t *testing.T) {
	t.Run("too many entries", func(t *testing.T) {
		es := []entry{{name: FileName, typeflag: tar.TypeReg, body: manifestWithContext(maxEntries + 1)}}
		for i := 0; i < maxEntries+1; i++ {
			es = append(es, entry{name: fmt.Sprintf("f%d", i), typeflag: tar.TypeReg, body: "x"})
		}
		_, err := UnpackTo(buildTar(t, es...), t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "entries") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("total size", func(t *testing.T) {
		big := strings.Repeat("a", maxFileSize)
		es := []entry{{name: FileName, typeflag: tar.TypeReg, body: manifestWithContext(10)}}
		for i := 0; i < 10; i++ {
			es = append(es, entry{name: fmt.Sprintf("f%d", i), typeflag: tar.TypeReg, body: big})
		}
		_, err := UnpackTo(buildTar(t, es...), t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "exceed") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("undeclared huge entry rejected by header", func(t *testing.T) {
		es := []entry{
			{name: FileName, typeflag: tar.TypeReg, body: fixtureYAML},
			{name: "huge.bin", typeflag: tar.TypeReg, body: strings.Repeat("a", maxFileSize)},
		}
		_, err := UnpackTo(buildTar(t, es...), t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "not declared") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("manifest must be first", func(t *testing.T) {
		es := []entry{
			{name: "docs/readme.md", typeflag: tar.TypeReg, body: "x"},
			{name: FileName, typeflag: tar.TypeReg, body: fixtureYAML},
		}
		if _, err := UnpackTo(buildTar(t, es...), t.TempDir()); err == nil {
			t.Fatal("expected error")
		}
	})
}
