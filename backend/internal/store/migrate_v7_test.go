package store

import (
	"reflect"
	"strings"
	"testing"
)

// makeV6 builds a database at schema version 6 by running the real migration
// steps 1-6 (never a copy of their SQL), with rows in every table a report
// refers to.
func makeV6(t *testing.T, dir string) {
	t.Helper()
	db := rawDB(t, dir)
	if err := migrate(db, migrations[:6]); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users(id, login) VALUES (1,'alice'),(2,'bob')`,
		`INSERT INTO bundles(owner_id, name) VALUES (1,'x'),(2,'y')`,
		`INSERT INTO versions(owner_id,name,version,digest,yanked,manifest,created_at,removed,removed_reason,size,readme) VALUES
			(1,'x','1.0.0','sha256:aa',0,'{"m":1}',100,0,'',10,'# hi'),
			(2,'y','0.1.0','sha256:cc',0,'{"m":3}',300,1,'spam',0,'')`,
		`INSERT INTO downloads(owner_id,name,version,day,count) SELECT 1,'x','1.0.0',CAST(strftime('%s','now') AS INTEGER)/86400,4`,
		`INSERT INTO banned_users(user_id,reason,created_at) VALUES (9,'bad',5)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

const v6Rows = `SELECT owner_id,name,version,digest,yanked,manifest,created_at,removed,removed_reason,size,readme FROM versions ORDER BY created_at`

func TestMigrateV6DatabaseAddsEmptyReports(t *testing.T) {
	dir := t.TempDir()
	makeV6(t, dir)
	before := dumpRows(t, rawDB(t, dir), v6Rows)
	beforeDL := dumpRows(t, rawDB(t, dir), `SELECT * FROM downloads`)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if v := schemaVersion(t, s.db); v != 9 || len(migrations) != 9 {
		t.Fatalf("schema_version = %d (%d steps), want 9", v, len(migrations))
	}
	if after := dumpRows(t, s.db, v6Rows); !reflect.DeepEqual(before, after) {
		t.Fatalf("existing rows changed:\n%v\n%v", before, after)
	}
	if after := dumpRows(t, s.db, `SELECT * FROM downloads`); !reflect.DeepEqual(beforeDL, after) {
		t.Fatalf("downloads changed: %v", after)
	}
	if n := dumpRows(t, s.db, `SELECT count(*) FROM reports`); n[0][0] != int64(0) {
		t.Fatalf("reports not empty: %v", n)
	}
	cols := dumpRows(t, s.db, `SELECT name, type, "notnull", dflt_value, pk FROM pragma_table_info('reports') ORDER BY cid`)
	want := [][]any{
		{"id", "INTEGER", int64(0), nil, int64(1)},
		{"owner_id", "INTEGER", int64(1), nil, int64(0)},
		{"name", "TEXT", int64(1), nil, int64(0)},
		{"version", "TEXT", int64(1), "''", int64(0)},
		{"reason", "TEXT", int64(1), nil, int64(0)},
		{"details", "TEXT", int64(1), "''", int64(0)},
		{"reporter_user_id", "INTEGER", int64(0), nil, int64(0)},
		{"reporter_key", "BLOB", int64(1), nil, int64(0)},
		{"created_at", "INTEGER", int64(1), nil, int64(0)},
		{"resolved_at", "INTEGER", int64(0), nil, int64(0)},
		{"resolved_by", "INTEGER", int64(0), nil, int64(0)},
		{"resolution", "TEXT", int64(1), "''", int64(0)},
	}
	if !reflect.DeepEqual(cols, want) {
		t.Fatalf("reports columns = %v", cols)
	}
	idx := dumpRows(t, s.db, `SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='reports' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if !reflect.DeepEqual(idx, [][]any{{"reports_dedup"}, {"reports_open"}}) {
		t.Fatalf("indexes = %v", idx)
	}
	first := schemaDump(t, s.db)
	s.Close()
	s2, err := Open(dir) // reopening changes nothing
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if v := schemaVersion(t, s2.db); v != 9 {
		t.Fatalf("version after reopen = %d", v)
	}
	if !reflect.DeepEqual(first, schemaDump(t, s2.db)) {
		t.Fatal("schema changed on reopen")
	}
}

func TestMigratedV6SchemaEqualsFresh(t *testing.T) {
	fresh, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	dir := t.TempDir()
	makeV6(t, dir)
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

// A release rolled back to v6 refuses a v7 database ("newer than this server
// supports"), so a rollback restores the pre-migration snapshot, and the
// reports table is recreated by rolling forward. What must hold on one file
// is that reports survive the v6 release's writes to the other tables.
func TestRollbackAndForwardKeepsReports(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	publish(t, s, 1, "alice", "x", "1.0.0")
	if _, err := s.db.Exec(`INSERT INTO reports(owner_id,name,version,reason,reporter_key,created_at) VALUES(1,'x','1.0.0','malware',x'01',5)`); err != nil {
		t.Fatal(err)
	}
	// What the v6 release's Publish did: a versions row, nothing else.
	if _, err := s.db.Exec(`INSERT INTO versions(owner_id,name,version,digest,manifest,created_at,size)
		VALUES(1,'x','1.1.0','sha256:zz','{}',9999999999,0)`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if n := dumpRows(t, s2.db, `SELECT count(*) FROM reports`); n[0][0] != int64(1) {
		t.Fatalf("reports after roll forward: %v", n)
	}
}
