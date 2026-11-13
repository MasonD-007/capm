package store

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// ScopePublish is the scope of tokens minted for CI (publish only). The auth
// and api packages name it too; a test keeps all three equal.
const ScopePublish = "publish"

// WriteAction is what a caller wants to do under an owner's namespace; it only
// changes how a CI token is treated (a publish-scoped token may publish, and
// nothing else).
type WriteAction int

const (
	ActPublish WriteAction = iota
	ActYank
	// ActRead is the owner-scoped views of the caller's own account (usage)
	// that members of an organisation may also see. Scoped tokens never get
	// it.
	ActRead
)

// DenyReason says why AuthorizeOwner refused.
type DenyReason int

const (
	// DenyNotOwner: the namespace is not the caller's, and is not an
	// organisation the caller may write to (or it does not exist, or is banned).
	DenyNotOwner DenyReason = iota + 1
	// DenyNotMember: the namespace is an organisation and the caller has no
	// record of being allowed to publish under it.
	DenyNotMember
	// DenyStale: the caller has a record, but it is older than OrgMembershipTTL.
	DenyStale
)

// Denial is a refusal. Org is the organisation's login for the two
// organisation reasons.
type Denial struct {
	Reason DenyReason
	Org    string
}

// Access is a granted authorisation to write under one namespace.
type Access struct {
	// Owner is the namespace's account: bundles and versions are stored under
	// Owner.ID (quotas, bans and downloads all key on it).
	Owner Account
	// PublishedBy is the acting user's id, nil when no human user acted (a CI
	// token of an organisation).
	PublishedBy *int64
}

// AuthorizeOwner is the ONE place that decides who may write (publish or
// yank) under the namespace ownerLogin, and who may see an owner's usage.
// Every owner-gated route goes through it (internal/api wraps it in
// authorizeOwner and a test enumerates the registered routes to prove it).
// Any lookup error is returned as err and the caller must refuse: nothing is
// ever granted on an error.
//
// tk has already been authenticated (it is unexpired and unrevoked and its
// user is not banned, which is re-checked here). The rules, in order:
//
//  1. The caller and the namespace's account must not be banned.
//  2. A publish-scoped (CI) token may publish only to the account it was
//     minted for, tk.UserID, never anywhere else whatever memberships its
//     actor has. The repository_owner_id recorded in its claims, when
//     present, must agree. It may not yank or read.
//  3. A full token may write to its own namespace (a user account; an
//     organisation has no interactive identity and never matches here).
//  4. A full token may write to an organisation when a record in org_members
//     (written by `capm login --orgs`) is at most OrgMembershipTTL old and
//     holds a role that may publish.
//  5. Everything else is refused.
func (s *Store) AuthorizeOwner(tk Token, ownerLogin string, act WriteAction) (Access, *Denial, error) {
	notOwner := &Denial{Reason: DenyNotOwner}

	if banned, err := s.IsBanned(tk.UserID); err != nil {
		return Access{}, nil, err
	} else if banned {
		return Access{}, notOwner, nil
	}
	acct, err := s.AccountByLogin(ownerLogin)
	found := true
	switch {
	case errors.Is(err, ErrNotFound):
		found = false
	case err != nil:
		return Access{}, nil, err
	}
	if !found {
		// No such account. A caller whose own login is the path may still
		// publish: their row is (re)written by the publish itself, as before.
		// A scoped token never reaches this: its account always exists.
		if tk.Scope == "" && tk.Kind != KindOrg && strings.EqualFold(ownerLogin, tk.Login) {
			by := tk.UserID
			return Access{Owner: Account{ID: tk.UserID, Login: tk.Login, Kind: KindUser}, PublishedBy: &by}, nil, nil
		}
		return Access{}, notOwner, nil
	}
	if banned, err := s.IsBanned(acct.ID); err != nil {
		return Access{}, nil, err
	} else if banned {
		return Access{}, notOwner, nil // same answer as a namespace that is not theirs
	}

	if tk.Scope != "" {
		if tk.Scope != ScopePublish || act != ActPublish || acct.ID != tk.UserID || !claimsOwnerMatches(tk.Claims, acct.ID) {
			return Access{}, notOwner, nil
		}
		if acct.Kind == KindOrg {
			return Access{Owner: acct}, nil, nil // no human user acted
		}
		by := acct.ID
		return Access{Owner: acct, PublishedBy: &by}, nil, nil
	}

	if tk.Kind == KindOrg {
		return Access{}, notOwner, nil // an organisation never acts interactively
	}
	if acct.Kind == KindUser && (acct.ID == tk.UserID || strings.EqualFold(acct.Login, tk.Login)) {
		// Today's rule: the caller's own login. (A different id holding the
		// caller's login is the login-reassignment case: the publish itself
		// re-records the login for the caller's id, see upsertAccount.
		// Tokens carry the login of their own row, so with real tokens the
		// two ids are always equal.)
		by := tk.UserID
		return Access{Owner: Account{ID: tk.UserID, Login: acct.Login, Kind: KindUser}, PublishedBy: &by}, nil, nil
	}
	if acct.Kind != KindOrg || acct.ID == tk.UserID {
		return Access{}, notOwner, nil
	}
	if _, ok, err := s.FreshOrgRole(acct.ID, tk.UserID); err != nil {
		return Access{}, nil, err
	} else if ok {
		by := tk.UserID
		return Access{Owner: acct, PublishedBy: &by}, nil, nil
	}
	has, err := s.HasStaleOrgRecord(acct.ID, tk.UserID)
	if err != nil {
		return Access{}, nil, err
	}
	if has {
		return Access{}, &Denial{Reason: DenyStale, Org: acct.Login}, nil
	}
	return Access{}, &Denial{Reason: DenyNotMember, Org: acct.Login}, nil
}

// claimsOwnerMatches cross-checks a CI token's recorded repository_owner_id
// against the account being written to. A token without the claim (minted
// before it was recorded) is bound by its account alone; a claim that is
// present must match, and claims that cannot be read refuse.
func claimsOwnerMatches(claims string, ownerID int64) bool {
	if claims == "" {
		return true
	}
	var m map[string]string
	if json.Unmarshal([]byte(claims), &m) != nil {
		return false
	}
	v, ok := m["repository_owner_id"]
	return !ok || v == strconv.FormatInt(ownerID, 10)
}
