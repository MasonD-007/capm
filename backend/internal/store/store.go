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
	"log"
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
	// OwnerKind is KindUser or KindOrg.
	OwnerKind string
	Name      string
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
	// PublishedVia is the compact JSON provenance record of a version
	// published with a CI token (see PublishVia); "" for every other version.
	PublishedVia string
	// OwnerKind is the owner account's kind (KindUser or KindOrg).
	OwnerKind string
	// PublishedBy is the login of the user who published the version when that
	// is not the owner (a member publishing for an organisation); "" for a
	// user's own namespace and when unknown (versions from before migration 9,
	// CI tokens of organisations).
	PublishedBy string
	// RepoVerified is true only for a version published by a CI token whose
	// verified repository claim equals the manifest's metadata.repository.
	RepoVerified bool
}

type Store struct {
	db       *sql.DB
	blobsDir string
	// blobMu serialises Publish's blob write+commit with a removal's commit+
	// unlink, so a removal can never delete a blob a concurrent publish just
	// re-used.
	blobMu sync.Mutex
	// now is the clock for token expiry and throttling; tests replace it.
	now func() time.Time
	// limits are the default quotas (see accounting.go); set once at startup.
	limits Limits
	// reportCapBundle and reportCapGlobal cap open reports (see reports.go).
	reportCapBundle, reportCapGlobal int
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
	if err := repairTokenIDs(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: repair token ids: %w", err)
	}
	if err := backfillSizes(db, blobs); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: backfill sizes: %w", err)
	}
	s := &Store{db: db, blobsDir: blobs, now: time.Now, limits: DefaultLimits(),
		reportCapBundle: MaxOpenReportsPerBundle, reportCapGlobal: MaxOpenReports}
	// Retention is housekeeping: a failure is logged and retried next start,
	// it never keeps the registry down.
	if err := s.rollupDownloads(); err != nil {
		log.Printf("store: download rollup failed (will retry at next start): %v", err)
	}
	return s, nil
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
	return s.PublishVia(ownerID, ownerLogin, name, version, tarball, "")
}

// PublishVia is Publish that also records via, the JSON provenance of a CI
// token ("" for none), in the same transaction as the version row.
func (s *Store) PublishVia(ownerID int64, ownerLogin, name, version string, tarball []byte, via string) error {
	return s.PublishAs(ownerID, ownerLogin, name, version, tarball, PublishMeta{Via: via})
}

// PublishMeta is what Publish records about who published a version.
type PublishMeta struct {
	// Via is the JSON provenance of a CI token ("" for none).
	Via string
	// PublishedBy is the acting user's id; nil when there is no human user
	// (a CI token of an organisation).
	PublishedBy *int64
}

// PublishAs is Publish with the publisher recorded in the same transaction as
// the version row.
func (s *Store) PublishAs(ownerID int64, ownerLogin, name, version string, tarball []byte, pm PublishMeta) error {
	via := pm.Via
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

	// "Verified" means exactly this: the version was published by a CI token
	// whose certified repository (recorded in via when the token was minted
	// from a verified ID token) is the repository the manifest names. It says
	// where the version was published from, nothing about its contents.
	verified := 0
	if pm.Via != "" {
		var rec map[string]string
		if json.Unmarshal([]byte(pm.Via), &rec) == nil && manifest.RepositoryMatches(m.Metadata.Repository, rec["repository"]) {
			verified = 1
		}
	}

	readme, err := readReadme(tmp)
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

	// The owner keeps the kind it already has (an organisation stays an
	// organisation); an id seen for the first time here is a user.
	kind := KindUser
	switch err := tx.QueryRow(`SELECT kind FROM users WHERE id = ?`, ownerID).Scan(&kind); {
	case errors.Is(err, sql.ErrNoRows):
		kind = KindUser
	case err != nil:
		return err
	}
	if err := upsertAccount(tx, ownerID, ownerLogin, kind); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO bundles(name, owner_id) VALUES(?, ?)`, name, ownerID); err != nil {
		return err
	}
	// Duplicates are reported before quota, so a rejected publish is never also
	// a duplicate. The quota check and the insert below are one transaction on
	// the store's only connection (and under blobMu), so no other publish can
	// run between the check and the insert: concurrent publishes serialise
	// and the second sees the first's row.
	dup, err := count(tx, `SELECT count(*) FROM versions WHERE owner_id = ? AND name = ? AND version = ?`, ownerID, name, version)
	if err != nil {
		return err
	}
	if dup > 0 {
		return ErrVersionExists
	}
	if err := s.checkQuota(tx, ownerID, name, "sha256:"+hexsum, int64(len(tarball))); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO versions(owner_id, name, version, digest, manifest, created_at, size, readme, published_via, published_by, repo_verified)
		VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, ownerID, name, version, "sha256:"+hexsum, string(mj), s.now().Unix(), len(tarball), readme, via, pm.PublishedBy, verified); err != nil {
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
	rows, err := s.db.Query(`SELECT v.owner_id, v.version, v.digest, v.yanked, v.manifest, v.created_at, v.removed, v.removed_reason, v.published_via,
		u.kind, CASE WHEN v.published_by = v.owner_id THEN '' ELSE COALESCE(pb.login, '') END, v.repo_verified
		FROM versions v JOIN users u ON u.id = v.owner_id LEFT JOIN users pb ON pb.id = v.published_by AND pb.login NOT LIKE '~%'
		WHERE u.login = ? AND v.name = ?`+notBanned+` ORDER BY v.created_at, v.rowid`, ownerLogin, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		var (
			v        Version
			mj       string
			yanked   int
			created  int64
			removed  int
			verified int
		)
		if err := rows.Scan(&v.OwnerID, &v.Version, &v.Digest, &yanked, &mj, &created, &removed, &v.RemovedReason, &v.PublishedVia,
			&v.OwnerKind, &v.PublishedBy, &verified); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(mj), &v.Manifest); err != nil {
			return nil, err
		}
		v.Yanked = yanked != 0
		v.Removed = removed != 0
		v.RepoVerified = verified != 0
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
	rows, err := s.db.Query(`SELECT u.id, u.login, u.kind, b.name FROM bundles b JOIN users u ON u.id = b.owner_id
		WHERE u.login NOT LIKE '~%' AND NOT EXISTS (SELECT 1 FROM banned_users bu WHERE bu.user_id = u.id) AND (? = '' OR u.login = ? COLLATE NOCASE)
		ORDER BY u.login, b.name LIMIT ? OFFSET ?`, owner, owner, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Bundle{}
	for rows.Next() {
		var b Bundle
		if err := rows.Scan(&b.Owner, &b.OwnerLogin, &b.OwnerKind, &b.Name); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

type execer interface {
	Exec(query string, args ...any) (sql.Result, error)
}
