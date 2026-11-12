package store

import (
	"database/sql"
	"fmt"
	"time"
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

// migrationNow is the clock migrations read; tests replace it.
var migrationNow = time.Now

var migrations = []migration{
	migrateV1,
	migrateV2,
	migrateV3,
	migrateV4,
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

// existingTokenLifetime is how long tokens issued before migration 3 keep
// working after it runs (decided: 90 days).
const existingTokenLifetime = 90 * 24 * time.Hour

// migrateV3 adds token management. tokens.hash stays the primary key; SQLite
// cannot add a PRIMARY KEY or UNIQUE column with ALTER TABLE, so id is a
// plain nullable INTEGER that is backfilled from rowid (distinct by
// construction) and then protected by a UNIQUE INDEX. Existing tokens expire
// existingTokenLifetime after the migration. The timestamp is computed once
// and passed as a parameter.
func migrateV3(tx *sql.Tx) error {
	exp := migrationNow().Add(existingTokenLifetime).Unix()
	for _, q := range []string{
		`ALTER TABLE tokens ADD COLUMN id INTEGER`,
		`ALTER TABLE tokens ADD COLUMN name TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE tokens ADD COLUMN expires_at INTEGER`,
		`ALTER TABLE tokens ADD COLUMN last_used_at INTEGER`,
		`ALTER TABLE tokens ADD COLUMN revoked_at INTEGER`,
		`UPDATE tokens SET id = rowid`,
		`CREATE UNIQUE INDEX tokens_id ON tokens(id)`,
	} {
		if _, err := tx.Exec(q); err != nil {
			return err
		}
	}
	_, err := tx.Exec(`UPDATE tokens SET expires_at = ?`, exp)
	return err
}

// migrateV4 adds storage quotas. versions.size is the byte length of the
// version's blob; it is nullable because a SQL step cannot see the blob files
// (NULL = unknown), and Open fills it in afterwards (backfillSizes), also for
// rows a rolled-back release inserted without it. quota_overrides holds a
// user's own limits; a NULL column means "use the default".
func migrateV4(tx *sql.Tx) error {
	_, err := tx.Exec(`
ALTER TABLE versions ADD COLUMN size INTEGER;
CREATE TABLE quota_overrides (
	user_id     INTEGER PRIMARY KEY,
	max_bytes   INTEGER,
	max_bundles INTEGER,
	updated_at  INTEGER NOT NULL
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
