package store

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	// ErrRemoved is matched (errors.Is) by the *RemovedError that Blob returns
	// for a version an admin has taken down.
	ErrRemoved        = errors.New("store: version removed")
	ErrAlreadyRemoved = errors.New("store: already removed")
	ErrNotRemoved     = errors.New("store: not removed")
	// ErrBlobMissing means a restore was refused because the tarball was
	// deleted when the version was removed.
	ErrBlobMissing   = errors.New("store: the bundle's data was deleted when it was removed and cannot be restored here")
	ErrAlreadyBanned = errors.New("store: user already banned")
	ErrNotBanned     = errors.New("store: user is not banned")
)

// RemovedError carries the admin's reason for a takedown.
type RemovedError struct{ Reason string }

func (e *RemovedError) Error() string        { return "store: version removed: " + e.Reason }
func (e *RemovedError) Is(target error) bool { return target == ErrRemoved }

// RemoveResult describes a removal: the versions newly removed and how many
// blob files were deleted (a blob still referenced by a live version of any
// owner is kept).
type RemoveResult struct {
	Versions     []string
	BlobsDeleted int
}

// RestoreResult describes a bundle restore: versions restored, and versions
// left removed because their blob no longer exists.
type RestoreResult struct {
	Restored []string
	Skipped  []string
}

// AdminAction is one audit-log row.
type AdminAction struct {
	ID         int64
	AdminID    int64
	AdminLogin string // "" if the admin never published or logged in
	Action     string
	Target     string
	Reason     string
	CreatedAt  time.Time
}

func (s *Store) blobFile(digest string) string {
	return filepath.Join(s.blobsDir, strings.TrimPrefix(digest, "sha256:"))
}

func audit(tx *sql.Tx, adminID int64, action, target, reason string) error {
	_, err := tx.Exec(`INSERT INTO admin_actions(admin_id, action, target, reason, created_at) VALUES(?,?,?,?,?)`,
		adminID, action, target, reason, time.Now().Unix())
	return err
}

func ownerID(tx *sql.Tx, login string) (int64, error) {
	if login == "" || strings.HasPrefix(login, "~") { // tombstoned ids are not addressable
		return 0, ErrNotFound
	}
	var id int64
	err := tx.QueryRow(`SELECT id FROM users WHERE login = ?`, login).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

type verRow struct {
	version, digest string
	removed         bool
}

func bundleVersions(tx *sql.Tx, owner int64, name string) ([]verRow, error) {
	rows, err := tx.Query(`SELECT version, digest, removed FROM versions
		WHERE owner_id = ? AND name = ? ORDER BY created_at, rowid`, owner, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []verRow
	for rows.Next() {
		var r verRow
		var rm int
		if err := rows.Scan(&r.version, &r.digest, &rm); err != nil {
			return nil, err
		}
		r.removed = rm != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// RemoveVersion takes down one version: it stays in the versions list (so the
// number can never be reused) but is marked removed with reason, and its blob
// is deleted unless a live version of any owner still references the digest.
// The change and its audit row commit together; the file is deleted after the
// commit, and a failure to delete it is logged, not returned.
func (s *Store) RemoveVersion(adminID int64, ownerLogin, name, version, reason string) (RemoveResult, error) {
	return s.remove(adminID, ownerLogin, name, version, reason, false)
}

// RemoveBundle takes down every live version of a bundle (see RemoveVersion).
func (s *Store) RemoveBundle(adminID int64, ownerLogin, name, reason string) (RemoveResult, error) {
	return s.remove(adminID, ownerLogin, name, "", reason, true)
}

func (s *Store) remove(adminID int64, ownerLogin, name, version, reason string, whole bool) (RemoveResult, error) {
	var res RemoveResult
	s.blobMu.Lock() // keeps Publish from re-using a blob between our commit and unlink
	defer s.blobMu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return res, err
	}
	defer tx.Rollback()
	owner, err := ownerID(tx, ownerLogin)
	if err != nil {
		return res, err
	}
	all, err := bundleVersions(tx, owner, name)
	if err != nil {
		return res, err
	}
	var targets []verRow
	for _, v := range all {
		if whole || v.version == version {
			if !v.removed {
				targets = append(targets, v)
			}
		}
	}
	if len(all) == 0 {
		return res, ErrNotFound
	}
	if !whole {
		found := false
		for _, v := range all {
			found = found || v.version == version
		}
		if !found {
			return res, ErrNotFound
		}
	}
	if len(targets) == 0 {
		return res, ErrAlreadyRemoved
	}
	for _, v := range targets {
		if _, err := tx.Exec(`UPDATE versions SET removed = 1, removed_reason = ?
			WHERE owner_id = ? AND name = ? AND version = ?`, reason, owner, name, v.version); err != nil {
			return res, err
		}
		res.Versions = append(res.Versions, v.version)
	}
	target := ownerLogin + "/" + name
	action := "remove_bundle"
	if !whole {
		target += "@" + version
		action = "remove_version"
	}
	if err := audit(tx, adminID, action, target, reason); err != nil {
		return res, err
	}
	var unlink []string
	seen := map[string]bool{}
	for _, v := range targets {
		if seen[v.digest] {
			continue
		}
		seen[v.digest] = true
		var live int
		if err := tx.QueryRow(`SELECT count(*) FROM versions WHERE digest = ? AND removed = 0`, v.digest).Scan(&live); err != nil {
			return res, err
		}
		if live == 0 {
			unlink = append(unlink, v.digest)
		}
	}
	if err := tx.Commit(); err != nil {
		return RemoveResult{}, err
	}
	for _, d := range unlink {
		if err := os.Remove(s.blobFile(d)); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("store: removed %s but could not delete blob %s: %v", target, d, err)
			continue
		}
		res.BlobsDeleted++
	}
	return res, nil
}

// RestoreVersion undoes RemoveVersion. It returns ErrBlobMissing, changing
// nothing, if the tarball was deleted and is no longer on disk.
func (s *Store) RestoreVersion(adminID int64, ownerLogin, name, version string) error {
	_, err := s.restore(adminID, ownerLogin, name, version, false)
	return err
}

// RestoreBundle restores every removed version of a bundle whose blob still
// exists. If none can be restored it returns ErrBlobMissing.
func (s *Store) RestoreBundle(adminID int64, ownerLogin, name string) (RestoreResult, error) {
	return s.restore(adminID, ownerLogin, name, "", true)
}

func (s *Store) restore(adminID int64, ownerLogin, name, version string, whole bool) (RestoreResult, error) {
	var res RestoreResult
	tx, err := s.db.Begin()
	if err != nil {
		return res, err
	}
	defer tx.Rollback()
	owner, err := ownerID(tx, ownerLogin)
	if err != nil {
		return res, err
	}
	all, err := bundleVersions(tx, owner, name)
	if err != nil {
		return res, err
	}
	if len(all) == 0 {
		return res, ErrNotFound
	}
	var cands []verRow
	found := false
	for _, v := range all {
		if !whole && v.version != version {
			continue
		}
		found = true
		if v.removed {
			cands = append(cands, v)
		}
	}
	if !found {
		return res, ErrNotFound
	}
	if len(cands) == 0 {
		return res, ErrNotRemoved
	}
	for _, v := range cands {
		if _, err := os.Stat(s.blobFile(v.digest)); err != nil {
			res.Skipped = append(res.Skipped, v.version)
			continue
		}
		if _, err := tx.Exec(`UPDATE versions SET removed = 0, removed_reason = ''
			WHERE owner_id = ? AND name = ? AND version = ?`, owner, name, v.version); err != nil {
			return res, err
		}
		res.Restored = append(res.Restored, v.version)
	}
	if len(res.Restored) == 0 {
		return res, ErrBlobMissing
	}
	target, action := ownerLogin+"/"+name, "restore_bundle"
	if !whole {
		target += "@" + version
		action = "restore_version"
	}
	if err := audit(tx, adminID, action, target, ""); err != nil {
		return res, err
	}
	if err := tx.Commit(); err != nil {
		return RestoreResult{}, err
	}
	return res, nil
}

// BanUser bans a GitHub user id. The user need not exist in the users table.
func (s *Store) BanUser(adminID, userID int64, reason string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO banned_users(user_id, reason, created_at) VALUES(?,?,?)`,
		userID, reason, time.Now().Unix()); err != nil {
		if isUnique(err) || isPK(err) {
			return ErrAlreadyBanned
		}
		return err
	}
	if err := audit(tx, adminID, "ban_user", fmt.Sprintf("user:%d", userID), reason); err != nil {
		return err
	}
	return tx.Commit()
}

// UnbanUser lifts a ban.
func (s *Store) UnbanUser(adminID, userID int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`DELETE FROM banned_users WHERE user_id = ?`, userID)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotBanned
	}
	if err := audit(tx, adminID, "unban_user", fmt.Sprintf("user:%d", userID), ""); err != nil {
		return err
	}
	return tx.Commit()
}

// IsBanned reports whether GitHub user id is banned.
func (s *Store) IsBanned(id int64) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT count(*) FROM banned_users WHERE user_id = ?`, id).Scan(&n)
	return n > 0, err
}

// UserIDByLogin resolves a login (case-insensitive) to a GitHub id.
func (s *Store) UserIDByLogin(login string) (int64, error) {
	if login == "" || strings.HasPrefix(login, "~") {
		return 0, ErrNotFound
	}
	var id int64
	err := s.db.QueryRow(`SELECT id FROM users WHERE login = ?`, login).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrNotFound
	}
	return id, err
}

// AdminLog returns the newest audit rows first.
func (s *Store) AdminLog(limit int) ([]AdminAction, error) {
	rows, err := s.db.Query(`SELECT a.id, a.admin_id, COALESCE(u.login, ''), a.action, a.target, a.reason, a.created_at
		FROM admin_actions a LEFT JOIN users u ON u.id = a.admin_id
		ORDER BY a.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdminAction{}
	for rows.Next() {
		var a AdminAction
		var ts int64
		if err := rows.Scan(&a.ID, &a.AdminID, &a.AdminLogin, &a.Action, &a.Target, &a.Reason, &ts); err != nil {
			return nil, err
		}
		a.CreatedAt = time.Unix(ts, 0).UTC()
		out = append(out, a)
	}
	return out, rows.Err()
}
