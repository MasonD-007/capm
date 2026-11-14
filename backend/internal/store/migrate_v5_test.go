package store

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// makeV4 builds a database at schema version 4 by running the real migration
// steps 1-4 (never a copy of their SQL), with a blob on disk for each live row
// so the size backfill has nothing to complain about.
func makeV4(t *testing.T, dir string) {
	t.Helper()
	db := rawDB(t, dir)
	if err := migrate(db, migrations[:4]); err != nil {
		t.Fatal(err)
	}
	blobs := filepath.Join(dir, "blobs")
	if err := os.MkdirAll(blobs, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, n := range map[string]int{"aa": 10, "bb": 20} {
		if err := os.WriteFile(filepath.Join(blobs, name), []byte(strings.Repeat("z", n)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{
		`INSERT INTO users(id, login) VALUES (1,'alice'),(2,'bob')`,
		`INSERT INTO bundles(owner_id, name) VALUES (1,'x'),(2,'y')`,
		`INSERT INTO versions(owner_id,name,version,digest,yanked,manifest,created_at,removed,removed_reason,size) VALUES
			(1,'x','1.0.0','sha256:aa',0,'{"m":1}',100,0,'',10),
			(1,'x','1.1.0','sha256:bb',1,'{"m":2}',200,0,'',20),
			(2,'y','0.1.0','sha256:cc',0,'{"m":3}',300,1,'spam',0)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

const v4Columns = `SELECT owner_id,name,version,digest,yanked,manifest,created_at,removed,removed_reason,size FROM versions ORDER BY created_at`

func TestMigrateV4KeepsRowsAndAddsEmptyReadme(t *testing.T) {
	dir := t.TempDir()
	makeV4(t, dir)
	before := dumpRows(t, rawDB(t, dir), v4Columns)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if v := schemaVersion(t, s.db); v != 10 {
		t.Fatalf("schema_version = %d, want 10", v)
	}
	if after := dumpRows(t, s.db, v4Columns); !reflect.DeepEqual(before, after) {
		t.Fatalf("existing columns changed:\n%v\n%v", before, after)
	}
	got := dumpRows(t, s.db, `SELECT readme FROM versions`)
	if len(got) != 3 {
		t.Fatalf("readme rows: %v", got)
	}
	for _, r := range got {
		if r[0] != "" {
			t.Fatalf("existing version has readme %q, want empty", r[0])
		}
	}
	for _, v := range []string{"1.0.0", "1.1.0"} {
		if rd, err := s.Readme("alice", "x", v); err != nil || rd != "" {
			t.Fatalf("Readme(%s) = %q, %v", v, rd, err)
		}
	}
	first := schemaDump(t, s.db)
	s.Close()
	s2, err := Open(dir) // reopening changes nothing
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if v := schemaVersion(t, s2.db); v != 10 {
		t.Fatalf("version after reopen = %d", v)
	}
	if !reflect.DeepEqual(first, schemaDump(t, s2.db)) {
		t.Fatal("schema changed on reopen")
	}
	// The migrated database accepts a publish with a README.
	if err := s2.Publish(1, "alice", "z", "1.0.0", bundleWith(t, "z", "1.0.0", map[string]string{"README.md": "# hi"})); err != nil {
		t.Fatal(err)
	}
	if rd, _ := s2.Readme("alice", "z", "1.0.0"); rd != "# hi" {
		t.Fatalf("readme = %q", rd)
	}
}

func TestMigratedV4SchemaEqualsFresh(t *testing.T) {
	fresh, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	dir := t.TempDir()
	makeV4(t, dir)
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

// After a rollback to the previous release, its Publish inserts rows without
// the readme column; the DEFAULT must make them readable after rolling
// forward.
func TestRowsFromRolledBackReleaseHaveEmptyReadme(t *testing.T) {
	s, _ := open(t)
	if _, err := s.db.Exec(`INSERT INTO versions(owner_id,name,version,digest,manifest,created_at,size)
		VALUES(1,'x','1.0.0','sha256:aa','{}',9,0)`); err != nil {
		t.Fatal(err)
	}
	var rd string
	if err := s.db.QueryRow(`SELECT readme FROM versions`).Scan(&rd); err != nil || rd != "" {
		t.Fatalf("readme = %q, %v", rd, err)
	}
}
