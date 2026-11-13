package api

import (
	"net/http"

	"github.com/MasonD-007/capm/backend/internal/store"
)

// ownerAction says which owner-gated operation is being authorised (it only
// changes the wording of a refusal).
type ownerAction int

const (
	actPublish ownerAction = iota
	actYank
)

// authorizeOwner is the route-facing side of store.AuthorizeOwner, the ONE
// place that decides who may write (publish or yank) under the namespace
// {owner}. Every route that acts on an owner's bundles as the caller goes
// through here, and a test enumerates the registered routes to prove it. It
// writes the refusal itself and reports ok=false; every lookup error is a
// refusal (500), never a grant. See store.AuthorizeOwner for the rules.
func (a *API) authorizeOwner(w http.ResponseWriter, r *http.Request, tk store.Token, ownerLogin string, act ownerAction) (store.Access, bool) {
	if a.authzHook != nil {
		a.authzHook(r.Pattern)
	}
	wa := store.ActPublish
	ownMsg := "you can only publish under your own login"
	if act == actYank {
		wa = store.ActYank
		ownMsg = "only the owner can yank or un-yank versions"
	}
	acc, den, err := a.store.AuthorizeOwner(tk, ownerLogin, wa)
	if err != nil {
		internal(w, err)
		return store.Access{}, false
	}
	if den == nil {
		return acc, true
	}
	switch den.Reason {
	case store.DenyStale:
		writeErr(w, 403, "your membership of "+den.Org+" was last checked more than 24 hours ago; run capm login --orgs again")
	case store.DenyNotMember:
		writeErr(w, 403, "you are not recorded as someone who may publish under "+den.Org+
			". Organisation owners (and members whose organisation grants write access) can run capm login --orgs to be recorded")
	default:
		writeErr(w, 403, ownMsg)
	}
	return store.Access{}, false
}
