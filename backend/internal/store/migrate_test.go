package store

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// v1Schema is the schema constant exactly as it was on main before the first
// migration existed. It is a frozen fixture: never edit it, so "a database
// created by v1" keeps its meaning however the live schema evolves.
const v1Schema = `
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
);`

const dsn = "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"

// makeV1 creates dir/capm.db the way the pre-migration code did and fills it.
func makeV1(t *testing.T, dir string) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "capm.db")+dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		v1Schema,
		`INSERT INTO users(id, login) VALUES (1,'alice'),(2,'bob'),(3,'~3')`,
		`INSERT INTO bundles(owner_id, name) VALUES (1,'x'),(2,'y')`,
		`INSERT INTO versions(owner_id,name,version,digest,yanked,manifest,created_at) VALUES
			(1,'x','1.0.0','sha256:aa',0,'{"m":1}',100),
			(1,'x','1.1.0','sha256:bb',1,'{"m":2}',200),
			(2,'y','0.1.0','sha256:cc',0,'{"m":3}',300)`,
		`INSERT INTO tokens(hash,user_id,created_at) VALUES (x'0102',1,50),(x'0304',2,60)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func rawDB(t *testing.T, dir string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "capm.db")+dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func schemaDump(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT type, name, sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var typ, name string
		var sq sql.NullString
		if err := rows.Scan(&typ, &name, &sq); err != nil {
			t.Fatal(err)
		}
		out = append(out, typ+" "+name+" "+sq.String)
	}
	return out
}

func dumpRows(t *testing.T, db *sql.DB, q string) [][]any {
	t.Helper()
	rows, err := db.Query(q)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out [][]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			t.Fatal(err)
		}
		out = append(out, vals)
	}
	return out
}

func schemaVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRow(`SELECT version FROM schema_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestMigrateV1Database(t *testing.T) {
	dir := t.TempDir()
	makeV1(t, dir)
	before := dumpRows(t, rawDB(t, dir), `SELECT * FROM users ORDER BY id`)

	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	db := s.db
	if v := schemaVersion(t, db); v != len(migrations) || v != 8 {
		t.Fatalf("schema_version = %d, want 8 (len(migrations)=%d)", v, len(migrations))
	}
	if got := dumpRows(t, db, `SELECT * FROM users ORDER BY id`); !reflect.DeepEqual(got, before) {
		t.Fatalf("users changed: %v vs %v", got, before)
	}
	var n int
	for tbl, want := range map[string]int{"users": 3, "bundles": 2, "versions": 3, "tokens": 2} {
		db.QueryRow(`SELECT count(*) FROM ` + tbl).Scan(&n)
		if n != want {
			t.Errorf("%s has %d rows, want %d", tbl, n, want)
		}
	}
	// Existing columns keep their values; new columns take their defaults.
	rows := dumpRows(t, db, `SELECT owner_id,name,version,digest,yanked,manifest,created_at,removed,removed_reason
		FROM versions ORDER BY created_at`)
	want := [][]any{
		{int64(1), "x", "1.0.0", "sha256:aa", int64(0), `{"m":1}`, int64(100), int64(0), ""},
		{int64(1), "x", "1.1.0", "sha256:bb", int64(1), `{"m":2}`, int64(200), int64(0), ""},
		{int64(2), "y", "0.1.0", "sha256:cc", int64(0), `{"m":3}`, int64(300), int64(0), ""},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("versions:\n got %v\nwant %v", rows, want)
	}
	for _, tbl := range []string{"banned_users", "admin_actions"} {
		if err := db.QueryRow(`SELECT count(*) FROM ` + tbl).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s: %v n=%d", tbl, err, n)
		}
	}
	if id, login, err := s.UserByTokenHash([]byte{1, 2}); err != nil || id != 1 || login != "alice" {
		t.Fatalf("token lookup: %d %q %v", id, login, err)
	}
	afterFirst := schemaDump(t, db)
	s.Close()

	// A second Open changes nothing.
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if v := schemaVersion(t, s2.db); v != 8 {
		t.Fatalf("version after reopen = %d", v)
	}
	if got := schemaDump(t, s2.db); !reflect.DeepEqual(got, afterFirst) {
		t.Fatalf("schema changed on reopen")
	}
	s2.db.QueryRow(`SELECT count(*) FROM versions`).Scan(&n)
	if n != 3 {
		t.Fatalf("versions rows = %d", n)
	}
	s2.db.QueryRow(`SELECT count(*) FROM schema_version`).Scan(&n)
	if n != 1 {
		t.Fatalf("schema_version has %d rows", n)
	}
}

func TestFreshAndMigratedSchemasIdentical(t *testing.T) {
	fresh, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	dir := t.TempDir()
	makeV1(t, dir)
	mig, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer mig.Close()
	a, b := schemaDump(t, fresh.db), schemaDump(t, mig.db)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("schemas differ:\nfresh:\n%s\nmigrated:\n%s", strings.Join(a, "\n"), strings.Join(b, "\n"))
	}
}

func TestMigratedDatabaseIsUsable(t *testing.T) {
	dir := t.TempDir()
	makeV1(t, dir)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Publish(1, "alice", "z", "1.0.0", bundle(t, "z", "1.0.0")); err != nil {
		t.Fatal(err)
	}
	vs, err := s.Versions("alice", "x")
	if err != nil || len(vs) != 2 {
		t.Fatalf("%v %v", vs, err)
	}
}

func TestMigrationFailureLeavesPreviousVersion(t *testing.T) {
	db := rawDB(t, t.TempDir())
	boom := errors.New("boom")
	steps := []migration{
		func(tx *sql.Tx) error { _, err := tx.Exec(`CREATE TABLE a(x INTEGER)`); return err },
		func(tx *sql.Tx) error {
			if _, err := tx.Exec(`CREATE TABLE b(x INTEGER)`); err != nil {
				return err
			}
			return boom // b must be rolled back along with the version bump
		},
	}
	if err := migrate(db, steps); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if v := schemaVersion(t, db); v != 1 {
		t.Fatalf("version = %d, want 1", v)
	}
	var n int
	db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name='a'`).Scan(&n)
	if n != 1 {
		t.Fatal("step 1 should be committed")
	}
	db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name='b'`).Scan(&n)
	if n != 0 {
		t.Fatal("failed step 2 left table b behind")
	}
	steps[1] = func(tx *sql.Tx) error { _, err := tx.Exec(`CREATE TABLE b(x INTEGER)`); return err }
	if err := migrate(db, steps); err != nil {
		t.Fatal(err)
	}
	if v := schemaVersion(t, db); v != 2 {
		t.Fatalf("version = %d, want 2", v)
	}
}

func TestOpenRefusesNewerDatabase(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(fmt.Sprintf(`UPDATE schema_version SET version = %d`, len(migrations)+1)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if _, err := Open(dir); err == nil || !strings.Contains(err.Error(), "newer") {
		t.Fatalf("err = %v", err)
	}
}
