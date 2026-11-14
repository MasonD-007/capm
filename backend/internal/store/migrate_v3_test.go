package store

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// makeV2 builds a database at schema version 2 by running the real migration
// steps 1 and 2 (never a copy of their SQL), then inserts tokens as the
// deployed v2 code would have.
func makeV2(t *testing.T, dir string) {
	t.Helper()
	db := rawDB(t, dir)
	if err := migrate(db, migrations[:2]); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users(id, login) VALUES (1,'alice'),(2,'bob')`,
		`INSERT INTO tokens(hash,user_id,created_at) VALUES (x'0102',1,50),(x'0304',2,60),(x'0506',1,70)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func TestMigrateV2ToV3Tokens(t *testing.T) {
	at := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	old := migrationNow
	migrationNow = func() time.Time { return at }
	defer func() { migrationNow = old }()

	dir := t.TempDir()
	makeV2(t, dir)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if v := schemaVersion(t, s.db); v != 10 || len(migrations) != 10 {
		t.Fatalf("schema_version = %d, len(migrations) = %d, want 10", v, len(migrations))
	}
	for _, h := range [][]byte{{1, 2}, {3, 4}, {5, 6}} {
		if _, _, err := s.UserByTokenHash(h); err != nil {
			t.Fatalf("token %x no longer resolves: %v", h, err)
		}
	}
	rows := dumpRows(t, s.db, `SELECT hash, user_id, created_at, id, name, expires_at, revoked_at FROM tokens ORDER BY created_at`)
	if len(rows) != 3 {
		t.Fatalf("rows = %v", rows)
	}
	wantExp := at.Add(90 * 24 * time.Hour).Unix()
	seen := map[int64]bool{}
	for _, r := range rows {
		id, ok := r[3].(int64)
		if !ok || id < 1 || seen[id] {
			t.Fatalf("bad or duplicate id in %v", rows)
		}
		seen[id] = true
		if r[4] != "" || r[5] != wantExp || r[6] != nil {
			t.Fatalf("row %v: want name '', expires_at %d, revoked NULL", r, wantExp)
		}
	}
	// New rows get a fresh id beyond the backfilled ones.
	if err := s.CreateToken([]byte{9, 9}, 1, "laptop", time.Time{}); err != nil {
		t.Fatal(err)
	}
	var newID int64
	s.db.QueryRow(`SELECT id FROM tokens WHERE hash = x'0909'`).Scan(&newID)
	if newID < 1 || seen[newID] {
		t.Fatalf("new id %d collides with %v", newID, seen)
	}
}

func TestMigratedV2SchemaEqualsFresh(t *testing.T) {
	fresh, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	dir := t.TempDir()
	makeV2(t, dir)
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

func TestMigrateV3NoopOnReopen(t *testing.T) {
	dir := t.TempDir()
	makeV2(t, dir)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	before := dumpRows(t, s.db, `SELECT * FROM tokens ORDER BY created_at`)
	s.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got := dumpRows(t, s2.db, `SELECT * FROM tokens ORDER BY created_at`); !reflect.DeepEqual(got, before) {
		t.Fatalf("tokens changed on reopen:\n%v\n%v", got, before)
	}
}

func TestMigrateV1StraightToV3KeepsTokens(t *testing.T) {
	dir := t.TempDir()
	makeV1(t, dir)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var n int
	s.db.QueryRow(`SELECT count(*) FROM tokens WHERE id IS NOT NULL AND expires_at IS NOT NULL`).Scan(&n)
	if n != 2 {
		t.Fatalf("%d tokens migrated with id and expiry, want 2", n)
	}
}
