package store

import (
	"reflect"
	"strings"
	"testing"
)

// makeV8 builds a database at schema version 8 by running the real migration
// steps 1-8 (never a copy of their SQL), with rows in the tables migration 9
// extends.
func makeV8(t *testing.T, dir string) {
	t.Helper()
	db := rawDB(t, dir)
	if err := migrate(db, migrations[:8]); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users(id, login) VALUES (1,'alice'),(2,'bob')`,
		`INSERT INTO bundles(owner_id, name) VALUES (1,'x')`,
		`INSERT INTO versions(owner_id,name,version,digest,yanked,manifest,created_at,removed,removed_reason,size,readme,published_via) VALUES
			(1,'x','1.0.0','sha256:aa',0,'{"m":1}',100,0,'',10,'# hi','{"repository":"alice/x"}')`,
		`INSERT INTO tokens(hash,user_id,created_at,id,name,expires_at,scope,claims) VALUES (x'01',1,5,1,'laptop',9999999999,'','')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

const v8VersionRows = `SELECT owner_id,name,version,digest,yanked,manifest,created_at,removed,size,readme,published_via FROM versions`

func TestMigrateV8DatabaseAddsOrgsAndProvenanceColumns(t *testing.T) {
	dir := t.TempDir()
	makeV8(t, dir)
	beforeTok := dumpRows(t, rawDB(t, dir), tokenRows)
	beforeVer := dumpRows(t, rawDB(t, dir), v8VersionRows)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if v := schemaVersion(t, s.db); v != 10 || len(migrations) != 10 {
		t.Fatalf("schema_version = %d (%d steps), want 10", v, len(migrations))
	}
	if after := dumpRows(t, s.db, tokenRows); !reflect.DeepEqual(beforeTok, after) {
		t.Fatalf("tokens changed:\n%v\n%v", beforeTok, after)
	}
	if after := dumpRows(t, s.db, v8VersionRows); !reflect.DeepEqual(beforeVer, after) {
		t.Fatalf("versions changed:\n%v\n%v", beforeVer, after)
	}
	// Existing accounts are users, existing versions are unverified and have
	// no recorded publisher.
	if got := dumpRows(t, s.db, `SELECT id, kind FROM users ORDER BY id`); !reflect.DeepEqual(got, [][]any{{int64(1), "user"}, {int64(2), "user"}}) {
		t.Fatalf("kinds = %v", got)
	}
	if got := dumpRows(t, s.db, `SELECT published_by, repo_verified FROM versions`); !reflect.DeepEqual(got, [][]any{{nil, int64(0)}}) {
		t.Fatalf("versions defaults = %v", got)
	}
	if got := dumpRows(t, s.db, `SELECT count(*) FROM org_members`); !reflect.DeepEqual(got, [][]any{{int64(0)}}) {
		t.Fatalf("org_members = %v", got)
	}
	// The kind column only accepts the two known values.
	if _, err := s.db.Exec(`UPDATE users SET kind = 'robot' WHERE id = 1`); err == nil {
		t.Fatal("users.kind accepted an unknown value")
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

func TestMigratedV8SchemaEqualsFresh(t *testing.T) {
	fresh, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	dir := t.TempDir()
	makeV8(t, dir)
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

// Rows written by a release that predates migration 9 omit the new columns
// and must get the defaults: an account is a user, a version is unverified
// with no recorded publisher.
func TestRolledBackReleaseRowsKeepV9Defaults(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Exactly what the previous release's upsertUser and Publish did.
	if _, err := s.db.Exec(`INSERT INTO users(id, login) VALUES(1, 'alice') ON CONFLICT(id) DO UPDATE SET login = excluded.login`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO versions(owner_id,name,version,digest,manifest,created_at,size,readme,published_via)
		VALUES(1,'x','1.0.0','sha256:zz','{}',9,0,'','')`); err != nil {
		t.Fatal(err)
	}
	if got := dumpRows(t, s.db, `SELECT kind FROM users`); !reflect.DeepEqual(got, [][]any{{"user"}}) {
		t.Fatalf("kind = %v", got)
	}
	if got := dumpRows(t, s.db, `SELECT published_by, repo_verified FROM versions`); !reflect.DeepEqual(got, [][]any{{nil, int64(0)}}) {
		t.Fatalf("defaults = %v", got)
	}
	vs, err := s.Versions("alice", "x")
	if err != nil || len(vs) != 1 || vs[0].RepoVerified || vs[0].PublishedBy != "" || vs[0].OwnerKind != "user" {
		t.Fatalf("%+v %v", vs, err)
	}
}
