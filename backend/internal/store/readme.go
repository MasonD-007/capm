package store

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/MasonD-007/capm/manifest"
)

// maxReadme caps the stored README text, in bytes.
const maxReadme = 64 << 10

const readmeTruncated = "\n[README truncated at 64 KiB]\n"

// readReadme returns the cleaned README.md at the root of an unpacked bundle,
// or "" if there is none. The name is matched exactly against the directory
// listing (not by opening the path, which a case-insensitive filesystem would
// answer for readme.md too), and only a regular file counts: a symlink is
// never followed. The bundle reader already refuses non-regular entries; this
// is the second line of defence.
func readReadme(dir string) (string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range ents {
		if e.Name() != manifest.ReadmeName || !e.Type().IsRegular() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return "", err
		}
		return cleanReadme(raw), nil
	}
	return "", nil
}

// cleanReadme turns file bytes into stored text: invalid UTF-8 and NUL bytes
// become U+FFFD (never rejected), and text over maxReadme bytes is cut at a
// rune boundary and ends with a marker line.
func cleanReadme(raw []byte) string {
	s := strings.ToValidUTF8(string(raw), "�")
	s = strings.ReplaceAll(s, "\x00", "�")
	if len(s) <= maxReadme {
		return s
	}
	cut := maxReadme
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + readmeTruncated
}

// Readme returns the README text stored with one version. It is "" when the
// version has none and for a removed version (a takedown may be about its
// content); ErrNotFound when the version does not exist. It is separate from
// Versions so listing bundles never loads README bodies.
func (s *Store) Readme(ownerLogin, name, version string) (string, error) {
	var (
		readme  string
		removed int
	)
	err := s.db.QueryRow(`SELECT v.readme, v.removed FROM versions v JOIN users u ON u.id = v.owner_id
		WHERE u.login = ? AND v.name = ? AND v.version = ?`+notBanned, ownerLogin, name, version).Scan(&readme, &removed)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if removed != 0 {
		return "", nil
	}
	return readme, nil
}
