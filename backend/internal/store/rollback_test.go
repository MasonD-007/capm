package store

import "testing"

// After a rollback to the previous release, its CreateToken inserts rows
// without an id. They must still authenticate, and rolling forward again must
// give them distinct ids.
func TestTokensWithoutIDFromRolledBackReleaseAreRepaired(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s.UpsertUser(1, "alice")
	for _, h := range []string{"\x01", "\x02"} {
		// Exactly what the v2 release's CreateToken did.
		if _, err := s.db.Exec(`INSERT INTO tokens(hash, user_id, created_at) VALUES(?, 1, 5)`, []byte(h)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.UserByTokenHash([]byte("\x01")); err != nil {
		t.Fatalf("token without id must still resolve: %v", err)
	}
	s.Close()

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var n, d int
	s2.db.QueryRow(`SELECT count(*), count(DISTINCT id) FROM tokens WHERE id IS NOT NULL`).Scan(&n, &d)
	if n != 2 || d != 2 {
		t.Fatalf("%d rows with an id, %d distinct", n, d)
	}
}
