package store

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func hexSum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

// makeV3 builds a database at schema version 3 by running the real migration
// steps 1-3 (never a copy of their SQL), with blob files on disk as the
// deployed v3 code would have left them. Versions: alice x@1.0.0 (blob aa, 10
// bytes), alice x@1.1.0 (yanked, blob bb, 20 bytes), bob y@0.1.0 (blob cc, 30
// bytes), bob y@0.2.0 (removed, blob dd deleted), alice x@2.0.0 re-using aa.
func makeV3(t *testing.T, dir string) {
	t.Helper()
	db := rawDB(t, dir)
	if err := migrate(db, migrations[:3]); err != nil {
		t.Fatal(err)
	}
	blobs := filepath.Join(dir, "blobs")
	if err := os.MkdirAll(blobs, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, n := range map[string]int{"aa": 10, "bb": 20, "cc": 30} {
		if err := os.WriteFile(filepath.Join(blobs, name), []byte(strings.Repeat("z", n)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{
		`INSERT INTO users(id, login) VALUES (1,'alice'),(2,'bob')`,
		`INSERT INTO bundles(owner_id, name) VALUES (1,'x'),(2,'y')`,
		`INSERT INTO versions(owner_id,name,version,digest,yanked,manifest,created_at,removed) VALUES
			(1,'x','1.0.0','sha256:aa',0,'{}',100,0),
			(1,'x','1.1.0','sha256:bb',1,'{}',200,0),
			(2,'y','0.1.0','sha256:cc',0,'{}',300,0),
			(2,'y','0.2.0','sha256:dd',0,'{}',400,1),
			(1,'x','2.0.0','sha256:aa',0,'{}',500,0)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
}

func sizes(t *testing.T, s *Store) [][]any {
	return dumpRows(t, s.db, `SELECT name, version, size FROM versions ORDER BY created_at`)
}

func TestMigrateV3BackfillsSizesFromBlobs(t *testing.T) {
	dir := t.TempDir()
	makeV3(t, dir)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if v := schemaVersion(t, s.db); v != 8 || len(migrations) != 8 {
		t.Fatalf("schema_version = %d, len(migrations) = %d, want 8", v, len(migrations))
	}
	want := [][]any{
		{"x", "1.0.0", int64(10)},
		{"x", "1.1.0", int64(20)},
		{"y", "0.1.0", int64(30)},
		{"y", "0.2.0", int64(0)}, // removed: blob deleted, so 0
		{"x", "2.0.0", int64(10)},
	}
	if got := sizes(t, s); !reflect.DeepEqual(got, want) {
		t.Fatalf("sizes:\n got %v\nwant %v", got, want)
	}
}

func TestBackfillIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	makeV3(t, dir)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	first := sizes(t, s)
	s.Close()
	// A blob appearing later must not change an already-decided size.
	if err := os.WriteFile(filepath.Join(dir, "blobs", "dd"), []byte("12345"), 0o644); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if got := sizes(t, s2); !reflect.DeepEqual(got, first) {
		t.Fatalf("sizes changed on reopen:\n%v\n%v", got, first)
	}
}

func TestMigratedV3SchemaEqualsFresh(t *testing.T) {
	fresh, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	dir := t.TempDir()
	makeV3(t, dir)
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
// a size. Rolling forward must repair them from the blob files.
func TestSizesFromRolledBackReleaseAreRepaired(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(1, "alice", "x", "1.0.0", bundle(t, "x", "1.0.0")); err != nil {
		t.Fatal(err)
	}
	// Exactly what the v3 release's Publish did: no size column.
	tb := bundle(t, "x", "1.1.0")
	h := hexSum(tb)
	if err := os.WriteFile(filepath.Join(dir, "blobs", h), tb, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO versions(owner_id,name,version,digest,manifest,created_at)
		VALUES(1,'x','1.1.0','sha256:'||?,'{}',9)`, h); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var n int
	s2.db.QueryRow(`SELECT count(*) FROM versions WHERE size IS NULL`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d rows still have NULL size", n)
	}
	var sz int64
	s2.db.QueryRow(`SELECT size FROM versions WHERE version = '1.1.0'`).Scan(&sz)
	if sz != int64(len(tb)) {
		t.Fatalf("size = %d, want %d", sz, len(tb))
	}
}
