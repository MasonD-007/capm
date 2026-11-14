package store

import (
	"reflect"
	"strings"
	"testing"
)

// makeV9 builds a database at schema version 9 by running the real migration
// steps 1-9 (never a copy of their SQL), with rows in the tables the new
// release reads next to the signatures table.
func makeV9(t *testing.T, dir string) {
	t.Helper()
	db := rawDB(t, dir)
	if err := migrate(db, migrations[:9]); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users(id, login) VALUES (1,'alice'),(2,'bob')`,
		`INSERT INTO bundles(owner_id, name) VALUES (1,'x')`,
		`INSERT INTO versions(owner_id,name,version,digest,yanked,manifest,created_at,removed,removed_reason,size,readme,published_via,published_by,repo_verified) VALUES
			(1,'x','1.0.0','sha256:aa',0,'{"m":1}',100,0,'',10,'# hi','',1,0)`,
		`INSERT INTO tokens(hash,user_id,created_at,id,name,expires_at,scope,claims) VALUES (x'01',1,5,1,'laptop',9999999999,'','')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

const v9VersionRows = `SELECT owner_id,name,version,digest,yanked,manifest,created_at,removed,size,readme,published_via,published_by,repo_verified FROM versions`

func TestMigrateV9DatabaseAddsSignaturesTable(t *testing.T) {
	dir := t.TempDir()
	makeV9(t, dir)
	beforeVer := dumpRows(t, rawDB(t, dir), v9VersionRows)
	beforeUsers := dumpRows(t, rawDB(t, dir), `SELECT id, login, kind FROM users ORDER BY id`)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if v := schemaVersion(t, s.db); v != 10 || len(migrations) != 10 {
		t.Fatalf("schema_version = %d (%d steps), want 10", v, len(migrations))
	}
	if after := dumpRows(t, s.db, v9VersionRows); !reflect.DeepEqual(beforeVer, after) {
		t.Fatalf("versions changed:\n%v\n%v", beforeVer, after)
	}
	if after := dumpRows(t, s.db, `SELECT id, login, kind FROM users ORDER BY id`); !reflect.DeepEqual(beforeUsers, after) {
		t.Fatalf("users changed:\n%v\n%v", beforeUsers, after)
	}
	// No existing version is signed, and the table works.
	if got := dumpRows(t, s.db, `SELECT count(*) FROM signatures`); !reflect.DeepEqual(got, [][]any{{int64(0)}}) {
		t.Fatalf("signatures = %v", got)
	}
	vs, err := s.Versions("alice", "x")
	if err != nil || len(vs) != 1 || vs[0].Signed {
		t.Fatalf("%+v %v", vs, err)
	}
	first := schemaDump(t, s.db)
	s.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if !reflect.DeepEqual(first, schemaDump(t, s2.db)) {
		t.Fatal("schema changed on reopen")
	}
}

func TestMigratedV9SchemaEqualsFresh(t *testing.T) {
	fresh, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	dir := t.TempDir()
	makeV9(t, dir)
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

// The release before this one neither reads nor writes signatures. After a
// rollback it can still publish, yank and remove on a database that has the
// table; a signature of a version it removes must stay invisible (and a
// restore by this release must not bring it back).
func TestRolledBackReleaseLeavesSignaturesConsistent(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Publish(1, "alice", "x", "1.0.0", bundle(t, "x", "1.0.0")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSignature(1, "x", "1.0.0", []byte(`{}`), nil); err != nil {
		t.Fatal(err)
	}
	// What the previous release's RemoveVersion did: it knew nothing of
	// signatures and only flagged the version.
	if _, err := s.db.Exec(`UPDATE versions SET removed = 1, removed_reason = 'x' WHERE owner_id = 1`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Signature("alice", "x", "1.0.0"); err == nil {
		t.Fatal("a removed version served a signature")
	}
	vs, _ := s.Versions("alice", "x")
	if len(vs) != 1 || vs[0].Signed {
		t.Fatalf("removed version reports signed: %+v", vs)
	}
	// This release restoring it drops the stale row.
	if err := s.RestoreVersion(99, "alice", "x", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Signature("alice", "x", "1.0.0"); err == nil {
		t.Fatal("restore brought a signature back")
	}
}
