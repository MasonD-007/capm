package store

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// makeV7 builds a database at schema version 7 by running the real migration
// steps 1-7 (never a copy of their SQL), with rows in the tables migration 8
// extends.
func makeV7(t *testing.T, dir string) {
	t.Helper()
	db := rawDB(t, dir)
	if err := migrate(db, migrations[:7]); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users(id, login) VALUES (1,'alice'),(2,'bob')`,
		`INSERT INTO bundles(owner_id, name) VALUES (1,'x')`,
		`INSERT INTO versions(owner_id,name,version,digest,yanked,manifest,created_at,removed,removed_reason,size,readme) VALUES
			(1,'x','1.0.0','sha256:aa',0,'{"m":1}',100,0,'',10,'# hi')`,
		`INSERT INTO tokens(hash,user_id,created_at,id,name,expires_at) VALUES (x'01',1,5,1,'laptop',9999999999),(x'02',2,6,2,'',NULL)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

const tokenRows = `SELECT hash,user_id,created_at,id,name,expires_at FROM tokens ORDER BY id`

func TestMigrateV7DatabaseAddsScopeClaimsAndProvenance(t *testing.T) {
	dir := t.TempDir()
	makeV7(t, dir)
	beforeTok := dumpRows(t, rawDB(t, dir), tokenRows)
	beforeVer := dumpRows(t, rawDB(t, dir), v6Rows)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if v := schemaVersion(t, s.db); v != 9 || len(migrations) != 9 {
		t.Fatalf("schema_version = %d (%d steps), want 9", v, len(migrations))
	}
	if after := dumpRows(t, s.db, tokenRows); !reflect.DeepEqual(beforeTok, after) {
		t.Fatalf("tokens changed:\n%v\n%v", beforeTok, after)
	}
	if after := dumpRows(t, s.db, v6Rows); !reflect.DeepEqual(beforeVer, after) {
		t.Fatalf("versions changed:\n%v\n%v", beforeVer, after)
	}
	// Existing rows get the defaults: full-power token, no provenance.
	if got := dumpRows(t, s.db, `SELECT scope, claims FROM tokens ORDER BY id`); !reflect.DeepEqual(got, [][]any{{"", ""}, {"", ""}}) {
		t.Fatalf("token defaults = %v", got)
	}
	if got := dumpRows(t, s.db, `SELECT published_via FROM versions`); !reflect.DeepEqual(got, [][]any{{""}}) {
		t.Fatalf("published_via default = %v", got)
	}
	for _, c := range []struct{ table, col string }{{"tokens", "scope"}, {"tokens", "claims"}, {"versions", "published_via"}} {
		got := dumpRows(t, s.db, `SELECT type, "notnull", dflt_value FROM pragma_table_info('`+c.table+`') WHERE name = '`+c.col+`'`)
		if !reflect.DeepEqual(got, [][]any{{"TEXT", int64(1), "''"}}) {
			t.Fatalf("%s.%s = %v", c.table, c.col, got)
		}
	}
	// Pre-existing tokens still authenticate and are unscoped.
	tk, err := s.LookupToken([]byte{1})
	if err != nil || tk.Scope != "" || tk.Claims != "" {
		t.Fatalf("lookup = %+v, %v", tk, err)
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

func TestMigratedV7SchemaEqualsFresh(t *testing.T) {
	fresh, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	dir := t.TempDir()
	makeV7(t, dir)
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

// Rows written by a release that predates migration 8 omit the new columns
// and must get the defaults: a token without scope is a full token, a version
// without provenance has none.
func TestRolledBackReleaseRowsKeepDefaults(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.UpsertUser(1, "alice")
	if _, err := s.db.Exec(`INSERT INTO tokens(hash, user_id, created_at, name, expires_at, id) VALUES(x'09', 1, 5, 'old', 9999999999, 77)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO versions(owner_id,name,version,digest,manifest,created_at,size,readme)
		VALUES(1,'x','1.0.0','sha256:zz','{}',9,0,'')`); err != nil {
		t.Fatal(err)
	}
	tk, err := s.LookupToken([]byte{9})
	if err != nil || tk.Scope != "" || tk.Claims != "" {
		t.Fatalf("token = %+v, %v", tk, err)
	}
	if got := dumpRows(t, s.db, `SELECT published_via FROM versions`); !reflect.DeepEqual(got, [][]any{{""}}) {
		t.Fatalf("published_via = %v", got)
	}
}

func TestScopedTokenRoundTrip(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.UpsertUser(1, "alice")
	exp := time.Now().Add(15 * time.Minute)
	if err := s.CreateScopedToken([]byte("h1"), 1, "ci:alice/x", exp, "publish", `{"repository":"alice/x"}`); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateToken([]byte("h2"), 1, "laptop", time.Time{}); err != nil {
		t.Fatal(err)
	}
	tk, err := s.LookupToken([]byte("h1"))
	if err != nil || tk.Scope != "publish" || tk.Claims != `{"repository":"alice/x"}` {
		t.Fatalf("lookup = %+v, %v", tk, err)
	}
	if tk, err := s.LookupToken([]byte("h2")); err != nil || tk.Scope != "" {
		t.Fatalf("full token = %+v, %v", tk, err)
	}
	list, err := s.ListTokens(1, nil)
	if err != nil || len(list) != 2 || list[0].Name != "ci:alice/x" || list[0].Scope != "publish" || list[1].Scope != "" {
		t.Fatalf("list = %+v, %v", list, err)
	}
}

func TestPublishViaIsStoredWithTheVersion(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	via := `{"repository":"alice/x","workflow_ref":"alice/x/.github/workflows/p.yml@refs/heads/main","sha":"abc"}`
	if err := s.PublishVia(1, "alice", "x", "1.0.0", bundle(t, "x", "1.0.0"), via); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(1, "alice", "x", "1.1.0", bundle(t, "x", "1.1.0")); err != nil {
		t.Fatal(err)
	}
	vs, err := s.Versions("alice", "x")
	if err != nil || len(vs) != 2 {
		t.Fatal(vs, err)
	}
	if vs[0].PublishedVia != via || vs[1].PublishedVia != "" {
		t.Fatalf("published via = %q, %q", vs[0].PublishedVia, vs[1].PublishedVia)
	}
}
