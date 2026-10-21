package store

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/MasonD-007/capm/manifest"
)

func bundle(t *testing.T, name, version string) []byte {
	t.Helper()
	dir := t.TempDir()
	y := "apiVersion: capm/v0\nkind: Agent\nmetadata: {name: " + name + ", version: " + version + "}\n" +
		"base: {agent: claude-code, version: 2.1.292}\ninterface: {type: tty}\n" +
		"model: {api: openai-compatible, requires: {toolCalling: true, minContextTokens: 1000}}\n"
	if err := os.WriteFile(filepath.Join(dir, manifest.FileName), []byte(y), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := manifest.PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rawTar(t *testing.T, entries map[string]string, order []string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, n := range order {
		tw.WriteHeader(&tar.Header{Name: n, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(entries[n]))})
		tw.Write([]byte(entries[n]))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func open(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

func TestPublishRoundTrip(t *testing.T) {
	s, _ := open(t)
	tb := bundle(t, "pr-reviewer", "0.1.0")
	if err := s.Publish(1, "alice", "pr-reviewer", "0.1.0", tb); err != nil {
		t.Fatal(err)
	}
	vs, err := s.Versions("alice", "pr-reviewer")
	if err != nil || len(vs) != 1 {
		t.Fatalf("versions: %v %v", vs, err)
	}
	sum := sha256.Sum256(tb)
	if want := "sha256:" + hex.EncodeToString(sum[:]); vs[0].Digest != want {
		t.Fatalf("digest %s want %s", vs[0].Digest, want)
	}
	if vs[0].Manifest.Metadata.Name != "pr-reviewer" || vs[0].CreatedAt.IsZero() {
		t.Fatalf("bad version %+v", vs[0])
	}
	got, err := s.Blob("alice", "pr-reviewer", "0.1.0")
	if err != nil || !bytes.Equal(got, tb) {
		t.Fatalf("blob mismatch: %v", err)
	}
	bs, err := s.List(10, 0)
	if err != nil || len(bs) != 1 || bs[0].OwnerLogin != "alice" || bs[0].Owner != 1 || bs[0].Name != "pr-reviewer" {
		t.Fatalf("list: %+v %v", bs, err)
	}
}

func TestDuplicateAndOwnership(t *testing.T) {
	s, _ := open(t)
	tb := bundle(t, "x", "1.0.0")
	if err := s.Publish(1, "alice", "x", "1.0.0", tb); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(1, "alice", "x", "1.0.0", tb); !errors.Is(err, ErrVersionExists) {
		t.Fatalf("got %v", err)
	}
	tb2 := bundle(t, "x", "1.1.0")
	if err := s.Publish(2, "bob", "x", "1.1.0", tb2); !errors.Is(err, ErrNameOwned) {
		t.Fatalf("got %v", err)
	}
	if err := s.Publish(1, "alice", "x", "1.1.0", tb2); err != nil {
		t.Fatal(err)
	}
}

func TestFailedPublishLeavesNoBlob(t *testing.T) {
	s, dir := open(t)
	tb := bundle(t, "x", "1.0.0")
	s.Publish(1, "alice", "x", "1.0.0", tb)
	other := bundle(t, "x", "1.0.1")
	if err := s.Publish(2, "bob", "x", "1.0.1", other); !errors.Is(err, ErrNameOwned) {
		t.Fatal(err)
	}
	if err := s.Publish(1, "alice", "x", "1.0.0", tb); !errors.Is(err, ErrVersionExists) {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(filepath.Join(dir, "blobs"))
	if len(ents) != 1 {
		t.Fatalf("want 1 blob, got %d", len(ents))
	}
}

func TestInvalid(t *testing.T) {
	s, dir := open(t)
	good := bundle(t, "x", "1.0.0")
	cases := map[string][]byte{
		"name mismatch":    bundle(t, "y", "1.0.0"),
		"version mismatch": bundle(t, "x", "2.0.0"),
		"not gzip":         []byte("hello"),
		"evil path":        rawTar(t, map[string]string{"capm.yaml": "x", "../evil": "x"}, []string{"../evil", "capm.yaml"}),
	}
	for n, tb := range cases {
		if err := s.Publish(1, "alice", "x", "1.0.0", tb); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v", n, err)
		}
	}
	_ = good
	ents, _ := os.ReadDir(filepath.Join(dir, "blobs"))
	if len(ents) != 0 {
		t.Fatalf("blobs left: %d", len(ents))
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dir), "evil")); err == nil {
		t.Fatal("evil written")
	}
}

func TestNotFound(t *testing.T) {
	s, _ := open(t)
	if _, err := s.Versions("nobody", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := s.Blob("nobody", "x", "1.0.0"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestListPaging(t *testing.T) {
	s, _ := open(t)
	for i, n := range []string{"a", "b", "c"} {
		if err := s.Publish(1, "alice", n, "1.0.0", bundle(t, n, "1.0.0")); err != nil {
			t.Fatal(i, err)
		}
	}
	bs, _ := s.List(2, 1)
	if len(bs) != 2 || bs[0].Name != "b" || bs[1].Name != "c" {
		t.Fatalf("%+v", bs)
	}
}
