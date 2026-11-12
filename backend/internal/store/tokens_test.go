package store

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"
)

func tokStore(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	s, _ := open(t)
	now := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	for i, l := range []string{"alice", "bob"} {
		if err := s.UpsertUser(int64(i+1), l); err != nil {
			t.Fatal(err)
		}
	}
	return s, &now
}

func TestExpiredTokenFailsLookup(t *testing.T) {
	s, now := tokStore(t)
	h := []byte("expiring")
	if err := s.CreateToken(h, 1, "", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UserByTokenHash(h); err != nil {
		t.Fatalf("live token: %v", err)
	}
	*now = now.Add(time.Hour) // expires_at == now counts as expired
	if _, _, err := s.UserByTokenHash(h); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired token: %v", err)
	}
}

func TestZeroExpiryNeverExpires(t *testing.T) {
	s, now := tokStore(t)
	h := []byte("forever")
	if err := s.CreateToken(h, 1, "", time.Time{}); err != nil {
		t.Fatal(err)
	}
	*now = now.AddDate(50, 0, 0)
	tk, err := s.LookupToken(h)
	if err != nil || !tk.ExpiresAt.IsZero() {
		t.Fatalf("%+v %v", tk, err)
	}
}

func TestRevokedTokenFailsLookup(t *testing.T) {
	s, _ := tokStore(t)
	h := []byte("tok")
	s.CreateToken(h, 1, "", time.Time{})
	tk, _ := s.LookupToken(h)
	if err := s.RevokeToken(1, tk.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UserByTokenHash(h); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoked token: %v", err)
	}
	if err := s.RevokeToken(1, tk.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke: %v", err)
	}
}

func TestRevokeOtherUsersTokenIsNotFound(t *testing.T) {
	s, _ := tokStore(t)
	s.CreateToken([]byte("a"), 1, "", time.Time{})
	tk, _ := s.LookupToken([]byte("a"))
	if err := s.RevokeToken(2, tk.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if _, _, err := s.UserByTokenHash([]byte("a")); err != nil {
		t.Fatalf("token was revoked by another user: %v", err)
	}
}

func TestLastUsedThrottledToOncePerHour(t *testing.T) {
	s, now := tokStore(t)
	h := []byte("tok")
	s.CreateToken(h, 1, "", time.Time{})
	lastUsed := func() (v *int64) {
		var n *int64
		s.db.QueryRow(`SELECT last_used_at FROM tokens WHERE hash = ?`, h).Scan(&n)
		return n
	}
	if lastUsed() != nil {
		t.Fatal("last_used_at should start NULL")
	}
	use := func() {
		tk, err := s.LookupToken(h)
		if err != nil {
			t.Fatal(err)
		}
		s.TouchToken(tk)
	}
	use()
	first := *lastUsed()
	if first != now.Unix() {
		t.Fatalf("first use not recorded: %d", first)
	}
	*now = now.Add(59 * time.Minute)
	use()
	if *lastUsed() != first {
		t.Fatal("updated again within the hour")
	}
	*now = now.Add(2 * time.Minute)
	use()
	if *lastUsed() != now.Unix() {
		t.Fatal("not updated after the hour")
	}
}

func TestTouchNeverFails(t *testing.T) {
	s, _ := tokStore(t)
	s.CreateToken([]byte("t"), 1, "", time.Time{})
	tk, _ := s.LookupToken([]byte("t"))
	s.db.Close() // the update will error; TouchToken has no error to return
	s.TouchToken(tk)
}

func TestListTokensNoHashAndOnlyOwnActive(t *testing.T) {
	s, now := tokStore(t)
	s.CreateToken([]byte("a1"), 1, "laptop", now.Add(time.Hour))
	s.CreateToken([]byte("a2"), 1, "", time.Time{})
	s.CreateToken([]byte("a3"), 1, "old", now.Add(-time.Hour))
	s.CreateToken([]byte("a4"), 1, "dead", time.Time{})
	s.CreateToken([]byte("b1"), 2, "bobs", time.Time{})
	dead, _ := s.LookupToken([]byte("a4"))
	if err := s.RevokeToken(1, dead.ID); err != nil {
		t.Fatal(err)
	}
	l, err := s.ListTokens(1, []byte("a2"))
	if err != nil {
		t.Fatal(err)
	}
	if len(l) != 2 {
		t.Fatalf("%+v", l)
	}
	if l[0].Name != "laptop" || l[0].Current || l[1].Name != "" || !l[1].Current {
		t.Fatalf("%+v", l)
	}
	if l[0].ExpiresAt.IsZero() || !l[1].ExpiresAt.IsZero() {
		t.Fatalf("expiry %+v", l)
	}
	if _, ok := reflect.TypeOf(l[0]).FieldByName("Hash"); ok {
		t.Fatal("TokenInfo must not carry the hash")
	}
}

func TestRevokeAllTokensAuditsAndSpares(t *testing.T) {
	s, _ := tokStore(t)
	s.CreateToken([]byte("a1"), 1, "", time.Time{})
	s.CreateToken([]byte("a2"), 1, "", time.Time{})
	s.CreateToken([]byte("b1"), 2, "", time.Time{})
	n, err := s.RevokeAllTokens(99, 1)
	if err != nil || n != 2 {
		t.Fatalf("%d %v", n, err)
	}
	for _, h := range []string{"a1", "a2"} {
		if _, _, err := s.UserByTokenHash([]byte(h)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s still valid", h)
		}
	}
	if _, _, err := s.UserByTokenHash([]byte("b1")); err != nil {
		t.Fatal("other user's token revoked")
	}
	log, _ := s.AdminLog(5)
	if len(log) != 1 || log[0].Action != "revoke_tokens" || log[0].Target != "user:1" || log[0].AdminID != 99 {
		t.Fatalf("%+v", log)
	}
	if n, err := s.RevokeAllTokens(99, 1); err != nil || n != 0 {
		t.Fatalf("second run %d %v", n, err)
	}
}

func TestConcurrentCreateTokenIDsUnique(t *testing.T) {
	s, _ := tokStore(t)
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := s.CreateToken([]byte(fmt.Sprintf("tok-%d", i)), 1, "", time.Time{}); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	var n, d int
	s.db.QueryRow(`SELECT count(*), count(DISTINCT id) FROM tokens WHERE id IS NOT NULL`).Scan(&n, &d)
	if n != 40 || d != 40 {
		t.Fatalf("%d rows, %d distinct ids", n, d)
	}
}

func TestPurgeTokens(t *testing.T) {
	s, now := tokStore(t)
	day := 24 * time.Hour
	s.CreateToken([]byte("expired-long"), 1, "", now.Add(-31*day))
	s.CreateToken([]byte("expired-recent"), 1, "", now.Add(-5*day))
	s.CreateToken([]byte("revoked-long"), 1, "", time.Time{})
	s.CreateToken([]byte("revoked-recent"), 1, "", time.Time{})
	s.CreateToken([]byte("live"), 1, "", time.Time{})
	rl, _ := s.LookupToken([]byte("revoked-long"))
	rr, _ := s.LookupToken([]byte("revoked-recent"))
	s.db.Exec(`UPDATE tokens SET revoked_at = ? WHERE id = ?`, now.Add(-31*day).Unix(), rl.ID)
	s.db.Exec(`UPDATE tokens SET revoked_at = ? WHERE id = ?`, now.Add(-day).Unix(), rr.ID)
	n, err := s.PurgeTokens()
	if err != nil || n != 2 {
		t.Fatalf("purged %d: %v", n, err)
	}
	var left int
	s.db.QueryRow(`SELECT count(*) FROM tokens`).Scan(&left)
	if left != 3 {
		t.Fatalf("%d rows left", left)
	}
}

func TestPurgeNeverFreesTheHighestID(t *testing.T) {
	s, now := tokStore(t)
	s.CreateToken([]byte("old"), 1, "", now.Add(-90*24*time.Hour))
	var oldID int64
	s.db.QueryRow(`SELECT id FROM tokens WHERE hash = ?`, []byte("old")).Scan(&oldID)
	if n, _ := s.PurgeTokens(); n != 0 {
		t.Fatalf("purged the row holding the highest id (%d)", n)
	}
	s.CreateToken([]byte("new"), 1, "", time.Time{})
	nw, _ := s.LookupToken([]byte("new"))
	if nw.ID <= oldID {
		t.Fatalf("id reused or went backwards: %d then %d", oldID, nw.ID)
	}
}
