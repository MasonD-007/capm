package manifest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// maxFileSize caps any single file in a bundle, in both directions.
const maxFileSize = 8 << 20

// PackDir validates dir/capm.yaml and returns a .tar.gz containing capm.yaml
// and exactly the declared context files.
func PackDir(dir string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	m, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := writeEntry(tw, FileName, raw); err != nil {
		return nil, err
	}
	seen := map[string]bool{FileName: true}
	for _, rel := range m.Context {
		name := path.Clean(filepath.ToSlash(rel))
		if seen[name] {
			continue
		}
		seen[name] = true
		data, err := readRegular(dir, name)
		if err != nil {
			return nil, fmt.Errorf("bundle: context file %q: %w", rel, err)
		}
		if err := writeEntry(tw, name, data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// readRegular reads dir/name, refusing symlinks (including in any parent
// component) and anything that is not a regular file.
func readRegular(dir, name string) ([]byte, error) {
	cur := dir
	parts := splitPath(name)
	for i, p := range parts {
		cur = filepath.Join(cur, p)
		fi, err := os.Lstat(cur)
		if err != nil {
			return nil, err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("is or traverses a symlink")
		}
		if i == len(parts)-1 {
			if !fi.Mode().IsRegular() {
				return nil, errors.New("not a regular file")
			}
			if fi.Size() > maxFileSize {
				return nil, errors.New("file too large")
			}
		}
	}
	return os.ReadFile(cur)
}

func splitPath(name string) []string { return strings.Split(name, "/") }

func writeEntry(tw *tar.Writer, name string, data []byte) error {
	h := &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data))}
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// UnpackTo extracts a bundle produced by PackDir into dest and returns its
// manifest. Nothing is written unless the whole archive is acceptable: only
// regular files, relative clean paths, capm.yaml plus declared context files.
func UnpackTo(tarball []byte, dest string) (*Manifest, error) {
	gz, err := gzip.NewReader(bytes.NewReader(tarball))
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	files := map[string][]byte{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("bundle: %w", err)
		}
		if h.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("bundle: entry %q is not a regular file", h.Name)
		}
		if !localPath(h.Name) || path.Clean(h.Name) != h.Name || filepath.ToSlash(h.Name) != h.Name {
			return nil, fmt.Errorf("bundle: entry %q has an unsafe path", h.Name)
		}
		if _, dup := files[h.Name]; dup {
			return nil, fmt.Errorf("bundle: duplicate entry %q", h.Name)
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxFileSize+1))
		if err != nil {
			return nil, fmt.Errorf("bundle: %w", err)
		}
		if len(data) > maxFileSize {
			return nil, fmt.Errorf("bundle: entry %q too large", h.Name)
		}
		files[h.Name] = data
	}

	raw, ok := files[FileName]
	if !ok {
		return nil, fmt.Errorf("bundle: missing %s", FileName)
	}
	m, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	allowed := make([]string, 0, len(m.Context))
	for _, c := range m.Context {
		allowed = append(allowed, path.Clean(filepath.ToSlash(c)))
	}
	for name := range files {
		if name != FileName && !slices.Contains(allowed, name) {
			return nil, fmt.Errorf("bundle: entry %q is not declared in context", name)
		}
	}

	for name, data := range files {
		target := filepath.Join(dest, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			return nil, err
		}
	}
	return m, nil
}
