// Package store persists published bundles: metadata in SQLite, tarballs as
// content-addressed blobs under DATA_DIR/blobs/<sha256>.
package store

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MasonD-007/capm/manifest"
	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

var (
	ErrVersionExists = errors.New("store: version already exists")
	ErrNotFound      = errors.New("store: not found")
	// ErrInvalid wraps problems with the submitted bundle; the message holds
	// the details and is safe to show to the publisher.
	ErrInvalid = errors.New("invalid bundle")
)

type Bundle struct {
	Owner      int64
	OwnerLogin string
	Name       string
}

type Version struct {
	Version   string
	Digest    string // "sha256:<hex>"
	Yanked    bool
	Manifest  manifest.Manifest
	CreatedAt time.Time
}

type Store struct {
	db       *sql.DB
	blobsDir string
}

const schema = `
CREATE TABLE IF NOT EXISTS users (
	id    INTEGER PRIMARY KEY,
	login TEXT NOT NULL UNIQUE COLLATE NOCASE
);
CREATE TABLE IF NOT EXISTS bundles (
	owner_id INTEGER NOT NULL REFERENCES users(id),
	name     TEXT NOT NULL,
	PRIMARY KEY(owner_id, name)
);
CREATE TABLE IF NOT EXISTS versions (
	owner_id   INTEGER NOT NULL,
	name       TEXT NOT NULL,
	version    TEXT NOT NULL,
	digest     TEXT NOT NULL,
	yanked     INTEGER NOT NULL DEFAULT 0,
	manifest   TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	UNIQUE(owner_id, name, version)
);`

// Open creates dataDir if needed and opens (migrating) the database in it.
func Open(dataDir string) (*Store, error) {
	blobs := filepath.Join(dataDir, "blobs")
	if err := os.MkdirAll(blobs, 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dataDir, "capm.db")+
		"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	// One connection serializes writers, which keeps publishes race-free.
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return &Store{db: db, blobsDir: blobs}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func isUnique(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE
}

// Publish validates tarball (it must be a well-formed bundle whose manifest
// name and version equal name and version) and stores it. The blob is written
// to a temp file, the row inserted in a transaction, and the blob renamed into
// place before commit; any failure leaves no new blob behind.
func (s *Store) Publish(ownerID int64, ownerLogin, name, version string, tarball []byte) error {
	tmp, err := os.MkdirTemp("", "capm-unpack-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	m, err := manifest.UnpackTo(tarball, tmp)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrInvalid, err)
	}
	if m.Metadata.Name != name || m.Metadata.Version != version {
		return fmt.Errorf("%w: manifest is %s@%s but URL says %s@%s",
			ErrInvalid, m.Metadata.Name, m.Metadata.Version, name, version)
	}
	mj, err := json.Marshal(m)
	if err != nil {
		return err
	}

	sum := sha256.Sum256(tarball)
	hexsum := hex.EncodeToString(sum[:])
	final := filepath.Join(s.blobsDir, hexsum)

	f, err := os.CreateTemp(s.blobsDir, ".tmp-")
	if err != nil {
		return err
	}
	tmpBlob := f.Name()
	defer os.Remove(tmpBlob) // no-op after a successful rename
	if _, err := f.Write(tarball); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// GitHub logins can be reassigned: free this login from any other id
	// (tombstone "~<id>" cannot match a URL owner) so logins stay unique.
	if _, err := tx.Exec(`UPDATE users SET login = '~' || id WHERE login = ? AND id != ?`, ownerLogin, ownerID); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO users(id, login) VALUES(?, ?)
		ON CONFLICT(id) DO UPDATE SET login = excluded.login`, ownerID, ownerLogin); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO bundles(name, owner_id) VALUES(?, ?)`, name, ownerID); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO versions(owner_id, name, version, digest, manifest, created_at)
		VALUES(?, ?, ?, ?, ?, ?)`, ownerID, name, version, "sha256:"+hexsum, string(mj), time.Now().Unix()); err != nil {
		if isUnique(err) {
			return ErrVersionExists
		}
		return err
	}

	_, statErr := os.Stat(final)
	existed := statErr == nil
	if err := os.Rename(tmpBlob, final); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		if !existed {
			os.Remove(final)
		}
		return err
	}
	return nil
}

func (s *Store) Versions(ownerLogin, name string) ([]Version, error) {
	rows, err := s.db.Query(`SELECT v.version, v.digest, v.yanked, v.manifest, v.created_at
		FROM versions v JOIN users u ON u.id = v.owner_id
		WHERE u.login = ? AND v.name = ? ORDER BY v.created_at, v.rowid`, ownerLogin, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		var (
			v       Version
			mj      string
			yanked  int
			created int64
		)
		if err := rows.Scan(&v.Version, &v.Digest, &yanked, &mj, &created); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(mj), &v.Manifest); err != nil {
			return nil, err
		}
		v.Yanked = yanked != 0
		v.CreatedAt = time.Unix(created, 0).UTC()
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

func (s *Store) Blob(ownerLogin, name, version string) ([]byte, error) {
	var digest string
	err := s.db.QueryRow(`SELECT v.digest FROM versions v JOIN users u ON u.id = v.owner_id
		WHERE u.login = ? AND v.name = ? AND v.version = ?`, ownerLogin, name, version).Scan(&digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(s.blobsDir, strings.TrimPrefix(digest, "sha256:")))
}

func (s *Store) List(limit, offset int) ([]Bundle, error) {
	rows, err := s.db.Query(`SELECT u.id, u.login, b.name FROM bundles b JOIN users u ON u.id = b.owner_id
		ORDER BY u.login, b.name LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Bundle{}
	for rows.Next() {
		var b Bundle
		if err := rows.Scan(&b.Owner, &b.OwnerLogin, &b.Name); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
