package store

import (
	"errors"
	"testing"
	"time"
)

func openClock(t *testing.T) (*Store, *time.Time) {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	now := time.Unix(1_800_000_000, 0)
	s.now = func() time.Time { return now }
	return s, &now
}

func TestOrgRowIsKeyedByIDWithKindOrg(t *testing.T) {
	s, _ := openClock(t)
	if err := s.UpsertOrg(77, "acme"); err != nil {
		t.Fatal(err)
	}
	a, err := s.AccountByLogin("ACME") // case-insensitive like users
	if err != nil || a.ID != 77 || a.Kind != KindOrg || a.Login != "acme" {
		t.Fatalf("%+v %v", a, err)
	}
	if err := s.UpsertUser(42, "alice"); err != nil {
		t.Fatal(err)
	}
	if a, err := s.AccountByLogin("alice"); err != nil || a.Kind != KindUser {
		t.Fatalf("%+v %v", a, err)
	}
	if _, err := s.AccountByLogin("nobody"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := s.AccountByLogin("~77"); !errors.Is(err, ErrNotFound) {
		t.Fatal("tombstones must not resolve")
	}
}

func TestOrgRenameAndLoginReuseTombstoneLikeUsers(t *testing.T) {
	s, _ := openClock(t)
	s.UpsertOrg(77, "acme")
	s.UpsertOrg(77, "acme2") // renamed
	if a, err := s.AccountByLogin("acme2"); err != nil || a.ID != 77 {
		t.Fatalf("%+v %v", a, err)
	}
	if _, err := s.AccountByLogin("acme"); !errors.Is(err, ErrNotFound) {
		t.Fatal("old login still resolves")
	}
	// Someone else takes the freed login: the id that held it is not it.
	s.UpsertUser(5, "acme2")
	if a, err := s.AccountByLogin("acme2"); err != nil || a.ID != 5 || a.Kind != KindUser {
		t.Fatalf("%+v %v", a, err)
	}
	var login string
	s.db.QueryRow(`SELECT login FROM users WHERE id = 77`).Scan(&login)
	if login != "~77" {
		t.Fatalf("org row login = %q, want tombstone", login)
	}
}

// GitHub user ids and organisation ids share one id space (both are
// "accounts"), so one table holds both; an id never changes kind.
func TestAccountIDNeverChangesKind(t *testing.T) {
	s, _ := openClock(t)
	s.UpsertUser(42, "alice")
	s.UpsertOrg(77, "acme")
	if err := s.UpsertOrg(42, "alice"); !errors.Is(err, ErrKindChange) {
		t.Fatalf("user id recorded as org: %v", err)
	}
	if err := s.UpsertUser(77, "acme"); !errors.Is(err, ErrKindChange) {
		t.Fatalf("org id recorded as user: %v", err)
	}
	// A refused upsert changes nothing, not even the login.
	if err := s.UpsertOrg(42, "renamed"); !errors.Is(err, ErrKindChange) {
		t.Fatal(err)
	}
	if a, err := s.AccountByLogin("alice"); err != nil || a.ID != 42 || a.Kind != KindUser {
		t.Fatalf("%+v %v", a, err)
	}
}

func TestPublishDoesNotChangeAnOrgsKindOrLogin(t *testing.T) {
	s, _ := openClock(t)
	s.UpsertOrg(77, "acme")
	if err := s.Publish(77, "acme", "x", "1.0.0", bundle(t, "x", "1.0.0")); err != nil {
		t.Fatal(err)
	}
	if a, err := s.AccountByLogin("acme"); err != nil || a.Kind != KindOrg {
		t.Fatalf("%+v %v", a, err)
	}
	s.UpsertUser(42, "alice")
	if err := s.PublishAs(42, "alice", "z", "1.0.0", bundle(t, "z", "1.0.0"), PublishMeta{}); err != nil {
		t.Fatal(err)
	}
}

func TestReplaceOrgMembershipsReplacesAllAndOnlyThatUsers(t *testing.T) {
	s, now := openClock(t)
	s.UpsertUser(42, "alice")
	s.UpsertUser(43, "bob")
	if err := s.ReplaceOrgMemberships(42, []OrgRecord{{77, "acme", RoleAdmin}, {78, "globex", RoleMember}}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceOrgMemberships(43, []OrgRecord{{77, "acme", RoleMember}}); err != nil {
		t.Fatal(err)
	}
	ms, err := s.OrgMemberships(42)
	if err != nil || len(ms) != 2 || ms[0].OrgLogin != "acme" || ms[0].Role != RoleAdmin || ms[1].OrgLogin != "globex" {
		t.Fatalf("%+v %v", ms, err)
	}
	if !ms[0].CheckedAt.Equal(*now) {
		t.Fatalf("checked at %v", ms[0].CheckedAt)
	}
	// Leaving globex: the next login records only acme.
	if err := s.ReplaceOrgMemberships(42, []OrgRecord{{77, "acme", RoleAdmin}}); err != nil {
		t.Fatal(err)
	}
	if ms, _ := s.OrgMemberships(42); len(ms) != 1 || ms[0].OrgLogin != "acme" {
		t.Fatalf("%+v", ms)
	}
	if ms, _ := s.OrgMemberships(43); len(ms) != 1 {
		t.Fatalf("another user's records changed: %+v", ms)
	}
	// An empty list removes every record.
	if err := s.ReplaceOrgMemberships(42, nil); err != nil {
		t.Fatal(err)
	}
	if ms, _ := s.OrgMemberships(42); len(ms) != 0 {
		t.Fatalf("%+v", ms)
	}
}

func TestReplaceOrgMembershipsRefusesAnIDThatIsAUser(t *testing.T) {
	s, _ := openClock(t)
	s.UpsertUser(42, "alice")
	s.UpsertUser(5, "mallory")
	// 5 is a user row; GitHub claims it is an org: no row, no membership.
	err := s.ReplaceOrgMemberships(42, []OrgRecord{{5, "mallory", RoleAdmin}, {77, "acme", RoleAdmin}})
	if err != nil {
		t.Fatal(err)
	}
	ms, _ := s.OrgMemberships(42)
	if len(ms) != 1 || ms[0].OrgID != 77 {
		t.Fatalf("%+v", ms)
	}
	if a, _ := s.AccountByLogin("mallory"); a.Kind != KindUser {
		t.Fatalf("%+v", a)
	}
}

func TestReplaceOrgMembershipsRejectsBadRolesAndIDs(t *testing.T) {
	s, _ := openClock(t)
	s.UpsertUser(42, "alice")
	for _, rec := range []OrgRecord{{77, "acme", "owner"}, {77, "acme", ""}, {0, "acme", RoleAdmin}, {77, "", RoleAdmin}, {77, "~x", RoleAdmin}} {
		if err := s.ReplaceOrgMemberships(42, []OrgRecord{rec}); err == nil {
			t.Errorf("%+v accepted", rec)
		}
	}
	if _, err := s.AccountByLogin("acme"); !errors.Is(err, ErrNotFound) {
		t.Fatal("a rejected record created an org row")
	}
}

func TestOrgMemberRoleFreshness(t *testing.T) {
	s, now := openClock(t)
	s.UpsertUser(42, "alice")
	s.ReplaceOrgMemberships(42, []OrgRecord{{77, "acme", RoleAdmin}})
	role, ok, err := s.FreshOrgRole(77, 42)
	if err != nil || !ok || role != RoleAdmin {
		t.Fatalf("%q %v %v", role, ok, err)
	}
	*now = now.Add(OrgMembershipTTL) // exactly 24h: still valid ("<= 24h")
	if _, ok, _ := s.FreshOrgRole(77, 42); !ok {
		t.Fatal("record at exactly the TTL must still be valid")
	}
	*now = now.Add(time.Second)
	if _, ok, err := s.FreshOrgRole(77, 42); ok || err != nil {
		t.Fatalf("stale record accepted: %v %v", ok, err)
	}
	if has, _ := s.HasStaleOrgRecord(77, 42); !has {
		t.Fatal("stale record not reported")
	}
	// A role the code does not know never qualifies, even when fresh.
	s.db.Exec(`UPDATE org_members SET role = 'guest', checked_at = ?`, now.Unix())
	if _, ok, _ := s.FreshOrgRole(77, 42); ok {
		t.Fatal("unknown role accepted")
	}
	// A record from the future (clock skew, tampering) is not fresh.
	s.db.Exec(`UPDATE org_members SET role = 'admin', checked_at = ?`, now.Add(time.Hour).Unix())
	if _, ok, _ := s.FreshOrgRole(77, 42); ok {
		t.Fatal("future-dated record accepted")
	}
}

func TestVersionsReportOwnerKindAndPublisher(t *testing.T) {
	s, _ := openClock(t)
	s.UpsertUser(42, "alice")
	s.UpsertOrg(77, "acme")
	by := int64(42)
	if err := s.PublishAs(77, "acme", "x", "1.0.0", bundle(t, "x", "1.0.0"), PublishMeta{PublishedBy: &by}); err != nil {
		t.Fatal(err)
	}
	if err := s.PublishAs(77, "acme", "x", "1.1.0", bundle(t, "x", "1.1.0"), PublishMeta{}); err != nil {
		t.Fatal(err)
	}
	vs, err := s.Versions("acme", "x")
	if err != nil || len(vs) != 2 {
		t.Fatal(vs, err)
	}
	if vs[0].OwnerKind != KindOrg || vs[0].PublishedBy != "alice" || vs[1].PublishedBy != "" {
		t.Fatalf("%+v %+v", vs[0], vs[1])
	}
	bs, err := s.ListByOwner("acme", 10, 0)
	if err != nil || len(bs) != 1 || bs[0].OwnerKind != KindOrg {
		t.Fatalf("%+v %v", bs, err)
	}
}

func TestBannedOrgIsHiddenAndQuotaIsPerOrg(t *testing.T) {
	s, _ := openClock(t)
	s.UpsertOrg(77, "acme")
	s.UpsertOrg(78, "globex")
	s.SetLimits(Limits{UserBundles: 1})
	if err := s.Publish(77, "acme", "x", "1.0.0", bundle(t, "x", "1.0.0")); err != nil {
		t.Fatal(err)
	}
	var qe *QuotaError
	if err := s.Publish(77, "acme", "y", "1.0.0", bundle(t, "y", "1.0.0")); !errors.As(err, &qe) || qe.Limit != LimitUserBundles {
		t.Fatalf("org not limited as owner: %v", err)
	}
	if err := s.Publish(78, "globex", "y", "1.0.0", bundle(t, "y", "1.0.0")); err != nil {
		t.Fatalf("another org shares the quota: %v", err)
	}
	if u, _ := s.Usage(77); u.Bundles != 1 {
		t.Fatalf("%+v", u)
	}
	if err := s.BanUser(1, 77, "bad org"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Versions("acme", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("banned org's bundle visible: %v", err)
	}
	if bs, _ := s.ListByOwner("acme", 10, 0); len(bs) != 0 {
		t.Fatalf("%+v", bs)
	}
	if id, err := s.UserIDByLogin("acme"); err != nil || id != 77 {
		t.Fatalf("admin login resolution must reach orgs: %d %v", id, err)
	}
}
