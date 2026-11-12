package store

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"strings"
	"testing"
	"unicode/utf8"
)

const readmeYAML = "apiVersion: capm/v0\nkind: Agent\nmetadata: {name: NAME, version: VER}\n" +
	"base: {agent: claude-code, version: 2.1.292}\ninterface: {type: tty}\n" +
	"model: {api: openai-compatible, requires: {toolCalling: true, minContextTokens: 1000}}\n"

// bundleWith builds a tarball by hand (capm.yaml first, then files) so tests
// can include entries PackDir would not write. context lists manifest context
// entries.
func bundleWith(t *testing.T, name, version string, files map[string]string, context ...string) []byte {
	t.Helper()
	y := strings.NewReplacer("NAME", name, "VER", version).Replace(readmeYAML)
	if len(context) > 0 {
		y += "context: [" + strings.Join(context, ", ") + "]\n"
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	put := func(n, body string) {
		if err := tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	put("capm.yaml", y)
	for n, b := range files {
		put(n, b)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func TestPublishStoresReadme(t *testing.T) {
	s, _ := open(t)
	if err := s.Publish(1, "alice", "x", "1.0.0", bundleWith(t, "x", "1.0.0", map[string]string{"README.md": "# Title\n\nbody é\n"})); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(1, "alice", "x", "1.1.0", bundle(t, "x", "1.1.0")); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Readme("alice", "x", "1.0.0"); err != nil || got != "# Title\n\nbody é\n" {
		t.Fatalf("got %q, %v", got, err)
	}
	if got, err := s.Readme("alice", "x", "1.1.0"); err != nil || got != "" {
		t.Fatalf("no README: got %q, %v", got, err)
	}
	if _, err := s.Readme("alice", "x", "9.9.9"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown version: %v", err)
	}
	if _, err := s.Readme("nobody", "x", "1.0.0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown owner: %v", err)
	}
}

func TestReadmeTruncatedAtUTF8Boundary(t *testing.T) {
	s, _ := open(t)
	// "é" is 2 bytes; the leading "a" puts the cap in the middle of a rune.
	body := "a" + strings.Repeat("é", 40000)
	if err := s.Publish(1, "alice", "x", "1.0.0", bundleWith(t, "x", "1.0.0", map[string]string{"README.md": body})); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Readme("alice", "x", "1.0.0")
	if !utf8.ValidString(got) {
		t.Fatal("truncated README is not valid UTF-8")
	}
	const marker = "\n[README truncated at 64 KiB]\n"
	if !strings.HasSuffix(got, marker) {
		t.Fatalf("missing marker, tail %q", got[len(got)-40:])
	}
	text := strings.TrimSuffix(got, marker)
	if len(text) > 64<<10 || len(text) < 64<<10-3 {
		t.Fatalf("kept %d bytes, want just under %d", len(text), 64<<10)
	}
	if strings.ContainsRune(text, utf8.RuneError) {
		t.Fatal("truncation produced a replacement character")
	}
	// Exactly at the cap is not truncated.
	exact := strings.Repeat("b", 64<<10)
	if err := s.Publish(1, "alice", "x", "1.1.0", bundleWith(t, "x", "1.1.0", map[string]string{"README.md": exact})); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Readme("alice", "x", "1.1.0"); got != exact {
		t.Fatalf("README of exactly the cap was altered (len %d)", len(got))
	}
}

func TestReadmeInvalidUTF8IsReplacedNotRejected(t *testing.T) {
	s, _ := open(t)
	if err := s.Publish(1, "alice", "x", "1.0.0", bundleWith(t, "x", "1.0.0", map[string]string{"README.md": "ok \xff\xfe bad\x00end"})); err != nil {
		t.Fatalf("invalid UTF-8 must not reject the publish: %v", err)
	}
	got, _ := s.Readme("alice", "x", "1.0.0")
	if !utf8.ValidString(got) || !strings.Contains(got, "ok �") || strings.ContainsRune(got, 0) {
		t.Fatalf("got %q", got)
	}
}

func TestOnlyRootRegularReadmeIsUsed(t *testing.T) {
	s, _ := open(t)
	// A nested README (declared in context so the bundle is valid) is not it.
	if err := s.Publish(1, "alice", "x", "1.0.0", bundleWith(t, "x", "1.0.0", map[string]string{"docs/README.md": "nested"}, "docs/README.md")); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Readme("alice", "x", "1.0.0"); got != "" {
		t.Fatalf("nested README used: %q", got)
	}
	// Different case is a different file.
	if err := s.Publish(1, "alice", "x", "1.1.0", bundleWith(t, "x", "1.1.0", map[string]string{"readme.md": "lower"}, "readme.md")); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Readme("alice", "x", "1.1.0"); got != "" {
		t.Fatalf("readme.md used: %q", got)
	}
	// A symlink or directory named README.md is rejected by the bundle reader
	// as before (only regular files are allowed), so nothing is followed.
	for _, h := range []tar.Header{
		{Name: "README.md", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		{Name: "README.md", Typeflag: tar.TypeDir},
	} {
		err := s.Publish(1, "alice", "x", "1.0.0", typedTar(t, h, ""))
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("%v: err = %v", h.Typeflag, err)
		}
	}
}

func TestReadmeNotServedForRemovedVersion(t *testing.T) {
	s, _ := open(t)
	if err := s.Publish(1, "alice", "x", "1.0.0", bundleWith(t, "x", "1.0.0", map[string]string{"README.md": "secret"})); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE versions SET removed = 1, removed_reason = 'bad'`); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Readme("alice", "x", "1.0.0"); err != nil || got != "" {
		t.Fatalf("removed version served %q, %v", got, err)
	}
}
