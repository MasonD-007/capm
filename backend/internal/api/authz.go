package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/MasonD-007/capm/backend/internal/store"
)

// ownerAction says which owner-gated operation is being authorised (it only
// changes the wording of a refusal).
type ownerAction int

const (
	actPublish ownerAction = iota
	actYank
)

// writeAccess is a granted authorisation to write under one namespace.
type writeAccess struct {
	// Owner is the namespace's account: bundles and versions are stored under
	// Owner.ID (quotas, bans and downloads all key on it).
	Owner store.Account
	// PublishedBy is the acting user's id, nil when no human user acted (a CI
	// token of an organisation).
	PublishedBy *int64
}

// authorizeOwner is the ONE place that decides who may write (publish or
// yank) under the namespace {owner}. Every route that acts on an owner's
// bundles as the caller goes through it, and a test enumerates the registered
// routes to prove it. It writes the refusal itself and reports ok=false;
// every lookup error is a refusal (500), never a grant.
//
// The rules, in order. tk has already been authenticated by caller (so it is
// unexpired, unrevoked and its user is not banned):
//
//  1. The namespace must resolve to an account; the owner must not be banned.
//  2. A publish-scoped (CI) token may write only to the account it was minted
//     for: tk.UserID. Never anywhere else, whatever memberships its user has.
//     The recorded repository_owner_id claim, when present, must agree.
//  3. A full token may write to its own namespace (a user account; an
//     organisation has no interactive identity and never matches here).
//  4. A full token may write to an organisation when a record in org_members
//     (written by `capm login --orgs`) is at most OrgMembershipTTL old and
//     holds a role that may publish; the caller and the organisation must not
//     be banned.
//  5. Everything else is refused.
func (a *API) authorizeOwner(w http.ResponseWriter, r *http.Request, tk store.Token, ownerLogin string, act ownerAction) (writeAccess, bool) {
	if a.authzHook != nil {
		a.authzHook(r.Pattern)
	}
	deny := func(msg string) (writeAccess, bool) {
		writeErr(w, 403, msg)
		return writeAccess{}, false
	}
	ownMsg := "you can only publish under your own login"
	if act == actYank {
		ownMsg = "only the owner can yank or un-yank versions"
	}

	// The caller's own ban, checked here as well as at authentication so that
	// no path through this function can grant a banned user anything.
	if banned, err := a.store.IsBanned(tk.UserID); err != nil {
		internal(w, err)
		return writeAccess{}, false
	} else if banned {
		return deny(ownMsg)
	}

	acct, err := a.store.AccountByLogin(ownerLogin)
	found := true
	switch {
	case errors.Is(err, store.ErrNotFound):
		found = false
	case err != nil:
		internal(w, err)
		return writeAccess{}, false
	}
	if !found {
		// No such account. A caller whose own login is the path may still
		// publish: their row is (re)written by the publish itself, as before.
		// A scoped token never reaches this: its account always exists.
		if tk.Scope == "" && tk.Kind != store.KindOrg && strings.EqualFold(ownerLogin, tk.Login) {
			by := tk.UserID
			return writeAccess{Owner: store.Account{ID: tk.UserID, Login: tk.Login, Kind: store.KindUser}, PublishedBy: &by}, true
		}
		return deny(ownMsg)
	}
	if banned, err := a.store.IsBanned(acct.ID); err != nil {
		internal(w, err)
		return writeAccess{}, false
	} else if banned {
		// Same answer as a namespace the caller has no right to.
		return deny(ownMsg)
	}

	if tk.Scope != "" {
		if tk.Scope != ScopePublish || act != actPublish || acct.ID != tk.UserID || !claimsOwnerMatches(tk.Claims, acct.ID) {
			return deny(ownMsg)
		}
		if acct.Kind == store.KindOrg {
			return writeAccess{Owner: acct}, true // no human user acted
		}
		by := acct.ID
		return writeAccess{Owner: acct, PublishedBy: &by}, true
	}

	if tk.Kind == store.KindOrg {
		return deny(ownMsg) // an organisation never acts interactively
	}
	if acct.Kind == store.KindUser && (acct.ID == tk.UserID || strings.EqualFold(acct.Login, tk.Login)) {
		// Today's rule: the caller's own login. (A different id holding the
		// caller's login is the login-reassignment case: the publish itself
		// re-records the login for the caller's id, see store.upsertAccount.
		// Tokens carry the login of their own row, so with real tokens the
		// two ids are always equal.)
		by := tk.UserID
		return writeAccess{Owner: store.Account{ID: tk.UserID, Login: acct.Login, Kind: store.KindUser}, PublishedBy: &by}, true
	}
	if acct.Kind != store.KindOrg || acct.ID == tk.UserID {
		return deny(ownMsg)
	}
	if _, ok, err := a.store.FreshOrgRole(acct.ID, tk.UserID); err != nil {
		internal(w, err)
		return writeAccess{}, false
	} else if ok {
		by := tk.UserID
		return writeAccess{Owner: acct, PublishedBy: &by}, true
	}
	if has, err := a.store.HasStaleOrgRecord(acct.ID, tk.UserID); err != nil {
		internal(w, err)
		return writeAccess{}, false
	} else if has {
		return deny("your membership of " + acct.Login + " was last checked more than 24 hours ago; run capm login --orgs again")
	}
	return deny("you are not recorded as someone who may publish under " + acct.Login +
		". Organisation owners (and members whose organisation grants write access) can run capm login --orgs to be recorded")
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
