package store

import (
	"database/sql"
	"fmt"
)

// A migration changes the schema from version N-1 to N, where N is its
// 1-based position in migrations. Each runs in its own transaction together
// with the schema_version bump, so a failure leaves the database at the
// previous version.
//
// Rules for adding one: append, never edit or reorder an existing step (a
// production database may already have run it); never drop or rebuild a table
// that holds data; ALTER TABLE ... ADD COLUMN ... NOT NULL needs a DEFAULT.
type migration func(tx *sql.Tx) error

var migrations = []migration{
	migrateV1,
	migrateV2,
}

// migrateV1 is the schema as it existed before migrations were introduced.
// Every statement is IF NOT EXISTS, so on a database created by that code
// (all tables already present) it changes nothing.
func migrateV1(tx *sql.Tx) error {
	_, err := tx.Exec(`
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
);
CREATE TABLE IF NOT EXISTS tokens (
	hash       BLOB PRIMARY KEY,
	user_id    INTEGER NOT NULL REFERENCES users(id),
	created_at INTEGER NOT NULL
);`)
	return err
}

// migrateV2 adds takedowns (versions.removed*), user bans and the admin audit
// log.
func migrateV2(tx *sql.Tx) error {
	_, err := tx.Exec(`
ALTER TABLE versions ADD COLUMN removed INTEGER NOT NULL DEFAULT 0;
ALTER TABLE versions ADD COLUMN removed_reason TEXT NOT NULL DEFAULT '';
CREATE TABLE banned_users (
	user_id    INTEGER PRIMARY KEY,
	reason     TEXT NOT NULL,
	created_at INTEGER NOT NULL
);
CREATE TABLE admin_actions (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	admin_id   INTEGER NOT NULL,
	action     TEXT NOT NULL,
	target     TEXT NOT NULL,
	reason     TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL
);`)
	return err
}

// migrate brings db up to len(steps). A database with no schema_version table
// is version 0 (either brand new, or created by the pre-migration code, which
// migration 1 leaves untouched).
func migrate(db *sql.DB, steps []migration) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)`); err != nil {
		return fmt.Errorf("create schema_version: %w", err)
	}
	cur, err := currentVersion(db)
	if err != nil {
		return err
	}
	if cur > len(steps) {
		return fmt.Errorf("database schema version %d is newer than this server supports (%d); refusing to start", cur, len(steps))
	}
	for i := cur; i < len(steps); i++ {
		if err := applyStep(db, i+1, steps[i]); err != nil {
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
	}
	return nil
}

func currentVersion(q interface {
	QueryRow(string, ...any) *sql.Row
}) (int, error) {
	var v int
	err := q.QueryRow(`SELECT version FROM schema_version`).Scan(&v)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return v, err
}

func applyStep(db *sql.DB, n int, step migration) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Re-check inside the transaction in case another process got here first.
	cur, err := currentVersion(tx)
	if err != nil {
		return err
	}
	if cur >= n {
		return nil
	}
	if err := step(tx); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM schema_version`); err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO schema_version(version) VALUES(?)`, n); err != nil {
		return err
	}
	return tx.Commit()
}
