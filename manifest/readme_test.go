package manifest

import (
	"archive/tar"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnpackAllowsRootReadmeOnly(t *testing.T) {
	good := entry{name: FileName, typeflag: tar.TypeReg, body: fixtureYAML}
	readme := entry{name: "README.md", typeflag: tar.TypeReg, body: "# hi"}
	dest := t.TempDir()
	if _, err := UnpackTo(buildTar(t, good, readme), dest); err != nil {
		t.Fatalf("root README.md must be allowed without being declared: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "README.md")); err != nil || string(b) != "# hi" {
		t.Fatalf("README.md not extracted: %q %v", b, err)
	}
	for _, name := range []string{"readme.md", "Readme.md", "docs/README.md", "README.md.txt", "README"} {
		if _, err := UnpackTo(buildTar(t, good, entry{name: name, typeflag: tar.TypeReg, body: "x"}), t.TempDir()); err == nil {
			t.Errorf("undeclared %q must still be rejected", name)
		}
	}
	for _, e := range []entry{
		{name: "README.md", typeflag: tar.TypeSymlink, link: "/etc/passwd"},
		{name: "README.md", typeflag: tar.TypeDir},
	} {
		if _, err := UnpackTo(buildTar(t, good, e), t.TempDir()); err == nil {
			t.Errorf("README.md of type %v must be rejected", e.typeflag)
		}
	}
	// It must still come after the manifest, and not twice.
	if _, err := UnpackTo(buildTar(t, readme, good), t.TempDir()); err == nil {
		t.Error("README.md before capm.yaml must be rejected")
	}
	if _, err := UnpackTo(buildTar(t, good, readme, readme), t.TempDir()); err == nil {
		t.Error("duplicate README.md must be rejected")
	}
}

func TestPackDirIncludesRootReadme(t *testing.T) {
	dir := writeFixture(t)
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# docs"), 0o644); err != nil {
		t.Fatal(err)
	}
	tb, err := PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if _, err := UnpackTo(tb, dest); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dest, "README.md")); string(b) != "# docs" {
		t.Fatalf("README.md not packed: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dest, "undeclared.txt")); err == nil {
		t.Fatal("undeclared file was packed")
	}
}

func TestPackDirIgnoresSymlinkedReadme(t *testing.T) {
	dir := writeFixture(t)
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("TOPSECRET"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(dir, "README.md")); err != nil {
		t.Skip("symlinks unavailable")
	}
	tb, err := PackDir(dir)
	if err != nil {
		t.Fatalf("a symlinked README.md is ignored, not an error: %v", err)
	}
	dest := t.TempDir()
	if _, err := UnpackTo(tb, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "README.md")); err == nil {
		t.Fatal("symlinked README.md was packed")
	}
}

func TestPackDirReadmeDeclaredInContextNotDuplicated(t *testing.T) {
	dir := writeFixture(t)
	y := strings.Replace(fixtureYAML, "context: [docs/readme.md]", "context: [README.md, docs/readme.md]", 1)
	os.WriteFile(filepath.Join(dir, FileName), []byte(y), 0o644)
	os.WriteFile(filepath.Join(dir, "README.md"), []byte("# docs"), 0o644)
	tb, err := PackDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnpackTo(tb, t.TempDir()); err != nil {
		t.Fatalf("duplicate README.md in archive: %v", err)
	}
}
