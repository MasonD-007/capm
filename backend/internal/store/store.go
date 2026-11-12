// Package store persists published bundles: metadata in SQLite, tarballs as
// content-addressed blobs under DATA_DIR/blobs/<sha256>.
package store

import (
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	// OwnerID is the owner's GitHub numeric id.
	OwnerID int64
	Version string
	Digest  string // "sha256:<hex>"
	Yanked  bool
	// Removed marks an admin takedown; RemovedReason is the admin's text
	// (untrusted by clients like any registry string).
	Removed       bool
	RemovedReason string
	Manifest      manifest.Manifest
	CreatedAt     time.Time
}

type Store struct {
	db       *sql.DB
	blobsDir string
	// blobMu serialises Publish's blob write+commit with a removal's commit+
	// unlink, so a removal can never delete a blob a concurrent publish just
	// re-used.
	blobMu sync.Mutex
}

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
	if err := migrate(db, migrations); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return &Store{db: db, blobsDir: blobs}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func isPK(err error) bool {
	var se *sqlite.Error
	return errors.As(err, &se) && se.Code() == sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY
}

// notBanned is a WHERE fragment (over versions aliased v) hiding versions of
// banned owners: their bundles answer exactly like bundles that don't exist.
const notBanned = ` AND NOT EXISTS (SELECT 1 FROM banned_users bu WHERE bu.user_id = v.owner_id)`

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

	s.blobMu.Lock()
	defer s.blobMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if err := upsertUser(tx, ownerID, ownerLogin); err != nil {
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
	rows, err := s.db.Query(`SELECT v.owner_id, v.version, v.digest, v.yanked, v.manifest, v.created_at, v.removed, v.removed_reason
		FROM versions v JOIN users u ON u.id = v.owner_id
		WHERE u.login = ? AND v.name = ?`+notBanned+` ORDER BY v.created_at, v.rowid`, ownerLogin, name)
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
			removed int
		)
		if err := rows.Scan(&v.OwnerID, &v.Version, &v.Digest, &yanked, &mj, &created, &removed, &v.RemovedReason); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(mj), &v.Manifest); err != nil {
			return nil, err
		}
		v.Yanked = yanked != 0
		v.Removed = removed != 0
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

// SetYanked marks or unmarks a version as yanked. Rows and blobs are never
// deleted. It returns ErrNotFound if ownerID has no such version.
func (s *Store) SetYanked(ownerID int64, name, version string, yanked bool) error {
	v := 0
	if yanked {
		v = 1
	}
	res, err := s.db.Exec(`UPDATE versions SET yanked = ? WHERE owner_id = ? AND name = ? AND version = ?`,
		v, ownerID, name, version)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Blob(ownerLogin, name, version string) ([]byte, error) {
	var (
		digest, reason string
		removed        int
	)
	err := s.db.QueryRow(`SELECT v.digest, v.removed, v.removed_reason FROM versions v JOIN users u ON u.id = v.owner_id
		WHERE u.login = ? AND v.name = ? AND v.version = ?`+notBanned, ownerLogin, name, version).Scan(&digest, &removed, &reason)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if removed != 0 {
		return nil, &RemovedError{Reason: reason}
	}
	return os.ReadFile(filepath.Join(s.blobsDir, strings.TrimPrefix(digest, "sha256:")))
}

func (s *Store) List(limit, offset int) ([]Bundle, error) {
	return s.ListByOwner("", limit, offset)
}

// ListByOwner is List restricted to one owner login (case-insensitive exact
// match); "" means every owner. A negative limit means no limit.
func (s *Store) ListByOwner(owner string, limit, offset int) ([]Bundle, error) {
	rows, err := s.db.Query(`SELECT u.id, u.login, b.name FROM bundles b JOIN users u ON u.id = b.owner_id
		WHERE u.login NOT LIKE '~%' AND NOT EXISTS (SELECT 1 FROM banned_users bu WHERE bu.user_id = u.id) AND (? = '' OR u.login = ? COLLATE NOCASE)
		ORDER BY u.login, b.name LIMIT ? OFFSET ?`, owner, owner, limit, offset)
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

type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// upsertUser records that GitHub user id currently has login. GitHub logins
// can be reassigned: any other id holding this login is tombstoned as
// "~<id>" (which cannot match a URL owner) so logins stay unique.
func upsertUser(x execer, id int64, login string) error {
	if _, err := x.Exec(`UPDATE users SET login = '~' || id WHERE login = ? AND id != ?`, login, id); err != nil {
		return err
	}
	_, err := x.Exec(`INSERT INTO users(id, login) VALUES(?, ?)
		ON CONFLICT(id) DO UPDATE SET login = excluded.login`, id, login)
	return err
}

// UpsertUser records the current login of a GitHub user.
func (s *Store) UpsertUser(id int64, login string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := upsertUser(tx, id, login); err != nil {
		return err
	}
	return tx.Commit()
}

// CreateToken stores the hash of an API token for userID. The raw token is
// never stored.
func (s *Store) CreateToken(hash []byte, userID int64) error {
	_, err := s.db.Exec(`INSERT INTO tokens(hash, user_id, created_at) VALUES(?, ?, ?)`,
		hash, userID, time.Now().Unix())
	return err
}

// UserByTokenHash resolves a token hash to the user's id and current login.
func (s *Store) UserByTokenHash(hash []byte) (int64, string, error) {
	var (
		id     int64
		login  string
		stored []byte
	)
	err := s.db.QueryRow(`SELECT u.id, u.login, t.hash FROM tokens t JOIN users u ON u.id = t.user_id
		WHERE t.hash = ?`, hash).Scan(&id, &login, &stored)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", ErrNotFound
	}
	if err != nil {
		return 0, "", err
	}
	if subtle.ConstantTimeCompare(stored, hash) != 1 {
		return 0, "", ErrNotFound
	}
	return id, login, nil
}
