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
	migrateV5,
	migrateV6,
	migrateV7,
	migrateV8,
	migrateV9,
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

// migrateV5 adds the README text extracted from a version's bundle at publish
// time. Existing versions keep ” (no backfill from blobs); a rolled-back
// release's Publish omits the column and gets the default.
func migrateV5(tx *sql.Tx) error {
	_, err := tx.Exec(`ALTER TABLE versions ADD COLUMN readme TEXT NOT NULL DEFAULT ''`)
	return err
}

// migrateV6 adds download counts: one row per (owner, name, version, UTC day)
// holding that day's request count (day = days since the Unix epoch; the
// sentinel day 0 holds the rolled-up history, see rollupDownloads). A pure
// table addition: a rolled-back release neither reads nor writes it, and
// versions it publishes simply have no rows (zero downloads).
//
// downloads_day exists for the 30-day aggregation, which filters on day alone
// (the primary key leads with owner_id, so it cannot serve that range). It
// covers owner_id, name, version and count, so the range scan never touches
// the table. Cost: each increment also updates this index.
func migrateV6(tx *sql.Tx) error {
	_, err := tx.Exec(`
CREATE TABLE downloads (
	owner_id INTEGER NOT NULL,
	name     TEXT NOT NULL,
	version  TEXT NOT NULL,
	day      INTEGER NOT NULL,
	count    INTEGER NOT NULL,
	PRIMARY KEY(owner_id, name, version, day)
);
CREATE INDEX downloads_day ON downloads(day, owner_id, name, version, count);`)
	return err
}

// migrateV7 adds abuse reports: one row per report of a bundle (version ”
// means the whole bundle). A pure table addition, so existing rows are never
// touched; a rolled-back release neither reads nor writes it (it would refuse
// to start on a version-7 database anyway, see migrate).
//
// reporter_key is an HMAC of the reporter's IP under a per-process salt, never
// the IP. Owner and name are not foreign keys (versions are immutable and
// never deleted, and a report must outlive any takedown).
//
// reports_open serves the admin list (open reports, newest first) and the
// global open-report count without touching the table; it is partial, so it
// stays as small as the open backlog, which is capped. reports_dedup serves
// the de-duplication lookup (same bundle, same reporter_key, recent) and,
// through its (owner_id, name) prefix, the per-bundle open-report cap. Cost:
// each insert updates both.
func migrateV7(tx *sql.Tx) error {
	_, err := tx.Exec(`
CREATE TABLE reports (
	id               INTEGER PRIMARY KEY AUTOINCREMENT,
	owner_id         INTEGER NOT NULL,
	name             TEXT NOT NULL,
	version          TEXT NOT NULL DEFAULT '',
	reason           TEXT NOT NULL,
	details          TEXT NOT NULL DEFAULT '',
	reporter_user_id INTEGER,
	reporter_key     BLOB NOT NULL,
	created_at       INTEGER NOT NULL,
	resolved_at      INTEGER,
	resolved_by      INTEGER,
	resolution       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX reports_open ON reports(created_at DESC, id DESC) WHERE resolved_at IS NULL;
CREATE INDEX reports_dedup ON reports(owner_id, name, reporter_key, created_at);`)
	return err
}

// migrateV8 adds token scopes and publish provenance (publishing from CI).
//
// tokens.scope: empty means a full token (every row that exists today, and every row
// an older release inserts, since it omits the column); "publish" may only
// publish. tokens.claims is the JSON of the OIDC claims recorded for a CI
// token. versions.published_via is a compact JSON record (repository,
// repository_id, workflow_ref, sha, run_id) for a version published with such
// a token, empty otherwise. Pure ADD COLUMN with constant defaults: no row is
// rewritten and nothing is rebuilt.
func migrateV8(tx *sql.Tx) error {
	_, err := tx.Exec(`
ALTER TABLE tokens ADD COLUMN scope TEXT NOT NULL DEFAULT '';
ALTER TABLE tokens ADD COLUMN claims TEXT NOT NULL DEFAULT '';
ALTER TABLE versions ADD COLUMN published_via TEXT NOT NULL DEFAULT '';`)
	return err
}

// migrateV9 adds organisation namespaces and verified repository links.
//
// users.kind: 'user' (every existing row, and every row a rolled-back release
// inserts, since it omits the column) or 'org'. GitHub user ids and
// organisation ids are one id space (both are "accounts"), which is why both
// live in users; the store refuses to ever change a recorded id's kind.
//
// org_members is a time-limited record that user_id may publish under org_id
// (see store.OrgMembershipTTL); it is rewritten at each `capm login --orgs`.
// Its primary key leads with org_id (the authorisation lookup); org_members_user
// serves "all of this user's records" (listing and replacing them).
//
// versions.published_by is the id of the acting user (NULL = unknown or a CI
// token of an organisation; existing rows stay NULL, meaning "the owner").
// versions.repo_verified is 1 only for a version published by a CI token whose
// verified repository claim equals the manifest's metadata.repository.
//
// Pure ADD COLUMN with constant defaults plus new objects: no row is rewritten
// and nothing is rebuilt.
func migrateV9(tx *sql.Tx) error {
	_, err := tx.Exec(`
ALTER TABLE users ADD COLUMN kind TEXT NOT NULL DEFAULT 'user' CHECK (kind IN ('user', 'org'));
CREATE TABLE org_members (
	org_id     INTEGER NOT NULL,
	user_id    INTEGER NOT NULL,
	role       TEXT NOT NULL,
	checked_at INTEGER NOT NULL,
	PRIMARY KEY(org_id, user_id)
);
CREATE INDEX org_members_user ON org_members(user_id);
ALTER TABLE versions ADD COLUMN published_by INTEGER;
ALTER TABLE versions ADD COLUMN repo_verified INTEGER NOT NULL DEFAULT 0;`)
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
