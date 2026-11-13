package store

import (
	"testing"
	"time"
)

func TestAuthorizeOwnerTable(t *testing.T) {
	s, now := openClock(t)
	for _, u := range []struct {
		id    int64
		login string
	}{{42, "alice"}, {43, "bob"}, {44, "carol"}, {45, "dave"}} {
		s.UpsertUser(u.id, u.login)
	}
	s.UpsertOrg(77, "acme")
	s.UpsertOrg(78, "globex")
	s.ReplaceOrgMemberships(42, []OrgRecord{{77, "acme", RoleAdmin}})
	s.ReplaceOrgMemberships(43, []OrgRecord{{77, "acme", RoleMember}})
	s.ReplaceOrgMemberships(45, []OrgRecord{{77, "acme", RoleAdmin}})
	s.BanUser(1, 45, "bad")
	ci := func(account int64, owner string) Token {
		return Token{UserID: account, Scope: ScopePublish, Claims: `{"repository_owner_id":"` + owner + `"}`}
	}
	full := func(id int64, login string) Token { return Token{UserID: id, Login: login, Kind: KindUser} }

	type want struct {
		ok     bool
		reason DenyReason
		owner  int64
		by     int64 // 0 = nil
	}
	cases := []struct {
		name  string
		tk    Token
		owner string
		act   WriteAction
		want  want
	}{
		{"own namespace", full(42, "alice"), "alice", ActPublish, want{true, 0, 42, 42}},
		{"own namespace, other case", full(42, "alice"), "ALICE", ActYank, want{true, 0, 42, 42}},
		{"someone else's namespace", full(42, "alice"), "bob", ActPublish, want{false, DenyNotOwner, 0, 0}},
		{"unknown namespace", full(42, "alice"), "nobody", ActPublish, want{false, DenyNotOwner, 0, 0}},
		{"tombstone", full(42, "alice"), "~77", ActPublish, want{false, DenyNotOwner, 0, 0}},
		{"org admin", full(42, "alice"), "acme", ActPublish, want{true, 0, 77, 42}},
		{"org member (write)", full(43, "bob"), "acme", ActYank, want{true, 0, 77, 43}},
		{"not a member", full(44, "carol"), "acme", ActPublish, want{false, DenyNotMember, 0, 0}},
		{"member of another org only", full(42, "alice"), "globex", ActPublish, want{false, DenyNotMember, 0, 0}},
		{"banned member", full(45, "dave"), "acme", ActPublish, want{false, DenyNotOwner, 0, 0}},
		{"org row used as a login", Token{UserID: 77, Login: "acme", Kind: KindOrg}, "acme", ActPublish, want{false, DenyNotOwner, 0, 0}},
		{"CI token, own account", ci(42, "42"), "alice", ActPublish, want{true, 0, 42, 42}},
		{"CI token of an org", ci(77, "77"), "acme", ActPublish, want{true, 0, 77, 0}},
		{"CI token of an org, other org", ci(77, "77"), "globex", ActPublish, want{false, DenyNotOwner, 0, 0}},
		{"CI token of an org, the actor's namespace", ci(77, "77"), "alice", ActPublish, want{false, DenyNotOwner, 0, 0}},
		{"CI token of a user, an org the user belongs to", ci(42, "42"), "acme", ActPublish, want{false, DenyNotOwner, 0, 0}},
		{"CI token, claim for another owner", ci(77, "42"), "acme", ActPublish, want{false, DenyNotOwner, 0, 0}},
		{"CI token cannot yank", ci(42, "42"), "alice", ActYank, want{false, DenyNotOwner, 0, 0}},
		{"CI token cannot read", ci(42, "42"), "alice", ActRead, want{false, DenyNotOwner, 0, 0}},
		{"unknown scope", Token{UserID: 42, Login: "alice", Scope: "admin"}, "alice", ActPublish, want{false, DenyNotOwner, 0, 0}},
	}
	for _, c := range cases {
		acc, den, err := s.AuthorizeOwner(c.tk, c.owner, c.act)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if (den == nil) != c.want.ok {
			t.Errorf("%s: denial = %+v, want ok=%v", c.name, den, c.want.ok)
			continue
		}
		if den != nil {
			if den.Reason != c.want.reason {
				t.Errorf("%s: reason %v, want %v", c.name, den.Reason, c.want.reason)
			}
			continue
		}
		var by int64
		if acc.PublishedBy != nil {
			by = *acc.PublishedBy
		}
		if acc.Owner.ID != c.want.owner || by != c.want.by {
			t.Errorf("%s: owner %d by %d, want %d by %d", c.name, acc.Owner.ID, by, c.want.owner, c.want.by)
		}
	}

	// Staleness is its own reason; a banned org is refused like any namespace
	// that is not theirs.
	*now = now.Add(OrgMembershipTTL + time.Second)
	if _, den, _ := s.AuthorizeOwner(full(42, "alice"), "acme", ActPublish); den == nil || den.Reason != DenyStale {
		t.Fatalf("stale: %+v", den)
	}
	s.ReplaceOrgMemberships(42, []OrgRecord{{77, "acme", RoleAdmin}})
	if _, den, _ := s.AuthorizeOwner(full(42, "alice"), "acme", ActPublish); den != nil {
		t.Fatalf("after refresh: %+v", den)
	}
	s.BanUser(1, 77, "org abuse")
	if _, den, _ := s.AuthorizeOwner(full(42, "alice"), "acme", ActPublish); den == nil || den.Reason != DenyNotOwner {
		t.Fatalf("banned org: %+v", den)
	}
	if _, den, _ := s.AuthorizeOwner(ci(77, "77"), "acme", ActPublish); den == nil {
		t.Fatal("banned org's CI token published")
	}
}

// A lookup that fails must never grant: closing the database makes every
// query an error.
func TestAuthorizeOwnerFailsClosedOnLookupErrors(t *testing.T) {
	s, _ := openClock(t)
	s.UpsertUser(42, "alice")
	s.UpsertOrg(77, "acme")
	s.ReplaceOrgMemberships(42, []OrgRecord{{77, "acme", RoleAdmin}})
	s.db.Close()
	for _, owner := range []string{"alice", "acme", "nobody"} {
		acc, den, err := s.AuthorizeOwner(Token{UserID: 42, Login: "alice", Kind: KindUser}, owner, ActPublish)
		if err == nil || den != nil || acc.Owner.ID != 0 {
			t.Errorf("%s: acc=%+v den=%+v err=%v", owner, acc, den, err)
		}
	}
}
