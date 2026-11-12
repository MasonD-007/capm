package store

import (
	"reflect"
	"strings"
	"testing"
)

// makeV5 builds a database at schema version 5 by running the real migration
// steps 1-5 (never a copy of their SQL), with a few rows in the tables that
// matter to downloads.
func makeV5(t *testing.T, dir string) {
	t.Helper()
	db := rawDB(t, dir)
	if err := migrate(db, migrations[:5]); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users(id, login) VALUES (1,'alice'),(2,'bob')`,
		`INSERT INTO bundles(owner_id, name) VALUES (1,'x'),(2,'y')`,
		`INSERT INTO versions(owner_id,name,version,digest,yanked,manifest,created_at,removed,removed_reason,size,readme) VALUES
			(1,'x','1.0.0','sha256:aa',0,'{"m":1}',100,0,'',10,'# hi'),
			(1,'x','1.1.0','sha256:bb',1,'{"m":2}',200,0,'',20,''),
			(2,'y','0.1.0','sha256:cc',0,'{"m":3}',300,1,'spam',0,'')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

const v5Columns = `SELECT owner_id,name,version,digest,yanked,manifest,created_at,removed,removed_reason,size,readme FROM versions ORDER BY created_at`

func TestMigrateV5DatabaseAddsEmptyDownloads(t *testing.T) {
	dir := t.TempDir()
	makeV5(t, dir)
	before := dumpRows(t, rawDB(t, dir), v5Columns)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if v := schemaVersion(t, s.db); v != 7 || len(migrations) != 7 {
		t.Fatalf("schema_version = %d (%d steps), want 7", v, len(migrations))
	}
	if after := dumpRows(t, s.db, v5Columns); !reflect.DeepEqual(before, after) {
		t.Fatalf("existing rows changed:\n%v\n%v", before, after)
	}
	if n := dumpRows(t, s.db, `SELECT count(*) FROM downloads`); n[0][0] != int64(0) {
		t.Fatalf("downloads not empty: %v", n)
	}
	cols := dumpRows(t, s.db, `SELECT name, type, "notnull", pk FROM pragma_table_info('downloads') ORDER BY cid`)
	want := [][]any{
		{"owner_id", "INTEGER", int64(1), int64(1)},
		{"name", "TEXT", int64(1), int64(2)},
		{"version", "TEXT", int64(1), int64(3)},
		{"day", "INTEGER", int64(1), int64(4)},
		{"count", "INTEGER", int64(1), int64(0)},
	}
	if !reflect.DeepEqual(cols, want) {
		t.Fatalf("downloads columns = %v", cols)
	}
	// Existing versions are countable.
	if err := s.CountDownload("alice", "x", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	first := schemaDump(t, s.db)
	s.Close()
	s2, err := Open(dir) // reopening changes nothing and keeps the count
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if v := schemaVersion(t, s2.db); v != 7 {
		t.Fatalf("version after reopen = %d", v)
	}
	if !reflect.DeepEqual(first, schemaDump(t, s2.db)) {
		t.Fatal("schema changed on reopen")
	}
	if n := dumpRows(t, s2.db, `SELECT sum(count) FROM downloads`); n[0][0] != int64(1) {
		t.Fatalf("count after reopen: %v", n)
	}
}

func TestMigratedV5SchemaEqualsFresh(t *testing.T) {
	fresh, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	dir := t.TempDir()
	makeV5(t, dir)
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

// A release rolled back to v5 ignores the downloads table (it neither counts
// nor reads it) but its publishes still work on the same file. Rolling
// forward keeps every count and gives versions the old release published
// zero downloads.
func TestRollbackAndForwardKeepsDownloadsConsistent(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	publish(t, s, 1, "alice", "x", "1.0.0")
	for i := 0; i < 3; i++ {
		if err := s.CountDownload("alice", "x", "1.0.0"); err != nil {
			t.Fatal(err)
		}
	}
	// What the old release's Publish did: a versions row, nothing else.
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
	got, err := s2.VersionDownloads("alice", "x")
	if err != nil {
		t.Fatal(err)
	}
	if got["1.0.0"].Total != 3 || got["1.1.0"].Total != 0 {
		t.Fatalf("counts after roll forward: %+v", got)
	}
}
