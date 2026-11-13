package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MasonD-007/capm/backend/internal/store"
)

// scopeReadOrg is the extra OAuth scope `capm login --orgs` asks GitHub for.
// Plain logins request no scope at all, exactly as before.
const scopeReadOrg = "read:org"

const (
	// maxMembershipPages bounds how many pages (of 100) of the user's
	// organisation memberships are read. Hitting it is reported to the user.
	maxMembershipPages = 10
	// maxBasePermissionLookups bounds the GET /orgs/{org} calls, one per
	// plain-member organisation.
	maxBasePermissionLookups = 50
	// orgPhaseTimeout bounds the whole organisation stage of a login; what has
	// not been checked by then is not recorded.
	orgPhaseTimeout = 30 * time.Second
	maxOrgReply     = 1 << 20
)

// orgsResult is the "orgs" member of the /v1/auth/token reply for a
// `--orgs` login. Recorded lists what may now be published under; Complete is
// false when the check was cut short or failed, with Note saying why in
// words for the user.
type orgsResult struct {
	Recorded []recordedOrg `json:"recorded"`
	Complete bool          `json:"complete"`
	Note     string        `json:"note,omitempty"`
}

type recordedOrg struct {
	Org  string `json:"org"`
	Role string `json:"role"`
}

// membership is one entry of GET /user/memberships/orgs.
type membership struct {
	State string `json:"state"`
	Role  string `json:"role"`
	Org   struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	} `json:"organization"`
}

// recordOrgs runs at the end of a successful `--orgs` login, while the
// service still holds the user's GitHub access token (which the caller
// discards afterwards; it is never stored or logged). It asks GitHub which
// organisations the user belongs to and records those under which they may
// publish. See qualifies for the rule. Every failure is fail closed: the
// organisation in question is not recorded, and a failure to read the list at
// all leaves the user's earlier records untouched (they expire on their own).
func (s *Service) recordOrgs(accessToken, grantedScope string, userID int64) orgsResult {
	res := orgsResult{Recorded: []recordedOrg{}}
	if !hasScope(grantedScope, scopeReadOrg) {
		res.Note = "GitHub did not grant the read:org permission, so no organisations were checked; run capm login --orgs again and approve it"
		return res
	}
	ctx, cancel := context.WithTimeout(context.Background(), orgPhaseTimeout)
	defer cancel()

	ms, complete, err := s.listMemberships(ctx, accessToken)
	if err != nil {
		log.Printf("auth: org memberships: %v", err)
		res.Note = "could not read your organisation memberships from GitHub; your earlier organisation records are unchanged. Try again shortly"
		return res
	}
	var recs []store.OrgRecord
	seen := map[int64]bool{}
	lookups := 0
	for _, m := range ms {
		if m.State != "active" || m.Org.ID <= 0 || !loginRe.MatchString(m.Org.Login) || seen[m.Org.ID] {
			continue
		}
		seen[m.Org.ID] = true
		switch m.Role {
		case "admin":
			// An organisation owner qualifies outright.
			recs = append(recs, store.OrgRecord{OrgID: m.Org.ID, Login: m.Org.Login, Role: store.RoleAdmin})
		case "member":
			if lookups >= maxBasePermissionLookups || ctx.Err() != nil {
				complete = false
				continue
			}
			lookups++
			ok, err := s.memberCanWrite(ctx, accessToken, m.Org.ID, m.Org.Login)
			if err != nil {
				log.Printf("auth: org base permission for org %d: %v", m.Org.ID, err)
				complete = false
				continue
			}
			if ok {
				recs = append(recs, store.OrgRecord{OrgID: m.Org.ID, Login: m.Org.Login, Role: store.RoleMember})
			}
		}
	}
	if err := s.store.ReplaceOrgMemberships(userID, recs); err != nil {
		log.Printf("auth: record org memberships: %v", err)
		res.Note = "could not record your organisation memberships; try again shortly"
		return res
	}
	// What the store accepted (it skips an id it holds as a user).
	have, err := s.store.OrgMemberships(userID)
	if err != nil {
		log.Printf("auth: read back org memberships: %v", err)
		res.Note = "could not record your organisation memberships; try again shortly"
		return res
	}
	for _, h := range have {
		res.Recorded = append(res.Recorded, recordedOrg{Org: h.OrgLogin, Role: h.Role})
	}
	res.Complete = complete
	if !complete {
		res.Note = "not all of your organisations were checked (GitHub returned too many, or part of the check failed), so some you belong to may be missing"
	}
	return res
}

func hasScope(granted, want string) bool {
	for _, f := range strings.FieldsFunc(granted, func(r rune) bool { return r == ',' || r == ' ' }) {
		if f == want {
			return true
		}
	}
	return false
}

// get performs an authenticated GET against GitHub's API at rawURL, which
// must be on the configured API host, and decodes the JSON reply into out. It
// returns the response headers.
func (s *Service) ghGet(ctx context.Context, accessToken, rawURL string, out any) (http.Header, error) {
	if !s.sameAPI(rawURL) {
		return nil, fmt.Errorf("refusing to call %q: not on the GitHub API host", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("github returned status " + resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxOrgReply)).Decode(out); err != nil {
		return nil, err
	}
	return resp.Header, nil
}

// sameAPI reports whether u is on the configured GitHub API origin. Pagination
// links come from GitHub's reply; the access token is only ever sent to the
// host the service was configured with.
func (s *Service) sameAPI(u string) bool {
	base, err := url.Parse(s.cfg.APIURL)
	if err != nil {
		return false
	}
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	return p.Scheme == base.Scheme && p.Host == base.Host && p.User == nil
}

// listMemberships reads the user's active organisation memberships, following
// Link rel="next" for at most maxMembershipPages pages. complete is false when
// pages remained. A failure on any page is an error: nothing partial is used.
func (s *Service) listMemberships(ctx context.Context, accessToken string) (all []membership, complete bool, err error) {
	next := s.cfg.APIURL + "/user/memberships/orgs?state=active&per_page=100"
	wantPath := s.apiPath("/user/memberships/orgs")
	for page := 0; page < maxMembershipPages; page++ {
		var ms []membership
		h, err := s.ghGet(ctx, accessToken, next, &ms)
		if err != nil {
			return nil, false, err
		}
		all = append(all, ms...)
		link := nextLink(h.Get("Link"))
		if link == "" {
			return all, true, nil
		}
		// Only follow a link that stays on this API, to this endpoint.
		if u, err := url.Parse(link); err != nil || !s.sameAPI(link) || u.Path != wantPath {
			log.Printf("auth: org memberships: ignoring unexpected pagination link")
			return all, false, nil
		}
		next = link
	}
	return all, false, nil
}

// apiPath is the path of an endpoint under the configured API URL (which may
// itself have a path prefix, as GitHub Enterprise does).
func (s *Service) apiPath(p string) string {
	base, err := url.Parse(s.cfg.APIURL)
	if err != nil {
		return p
	}
	return strings.TrimRight(base.Path, "/") + p
}

// nextLink extracts the rel="next" URL of an RFC 8288 Link header, or "".
func nextLink(h string) string {
	for _, part := range strings.Split(h, ",") {
		target, params, ok := strings.Cut(part, ";")
		if !ok {
			continue
		}
		target = strings.TrimSpace(target)
		if !strings.HasPrefix(target, "<") || !strings.HasSuffix(target, ">") {
			continue
		}
		for _, p := range strings.Split(params, ";") {
			if k, v, _ := strings.Cut(strings.TrimSpace(p), "="); k == "rel" && strings.Trim(v, `"`) == "next" {
				return target[1 : len(target)-1]
			}
		}
	}
	return ""
}

// memberCanWrite is the rule for a plain (non-owner) member: the organisation's
// default_repository_permission must be returned by GitHub, and be exactly
// "write" or "admin". The field is only returned to callers with enough
// visibility, so for most plain members it is absent, and then the member does
// not qualify: absent, null, any other value, a failed call and an answer
// about a different organisation all mean no. Team-specific write access is
// not consulted (not supported in this version).
func (s *Service) memberCanWrite(ctx context.Context, accessToken string, orgID int64, login string) (bool, error) {
	var o struct {
		ID    int64   `json:"id"`
		Login string  `json:"login"`
		Perm  *string `json:"default_repository_permission"`
	}
	if _, err := s.ghGet(ctx, accessToken, s.cfg.APIURL+"/orgs/"+url.PathEscape(login), &o); err != nil {
		return false, err
	}
	if o.ID != orgID || !strings.EqualFold(o.Login, login) {
		return false, fmt.Errorf("github returned a different organisation for %q", login)
	}
	return o.Perm != nil && (*o.Perm == "write" || *o.Perm == "admin"), nil
}

// listOrgs answers GET /v1/auth/orgs: the organisations the caller has a
// record for (fresh or not), with when each record stops authorising.
func (s *Service) listOrgs(w http.ResponseWriter, r *http.Request) {
	tk, _, ok := s.requireFull(w, r)
	if !ok {
		return
	}
	ms, err := s.store.OrgMemberships(tk.UserID)
	if err != nil {
		log.Printf("auth: list orgs: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	type item struct {
		Org       string `json:"org"`
		Role      string `json:"role"`
		CheckedAt string `json:"checkedAt"`
		ExpiresAt string `json:"expiresAt"`
		Expired   bool   `json:"expired"`
	}
	out := make([]item, 0, len(ms))
	for _, m := range ms {
		exp := m.CheckedAt.Add(store.OrgMembershipTTL)
		out = append(out, item{m.OrgLogin, m.Role, m.CheckedAt.Format(time.RFC3339), exp.Format(time.RFC3339), !m.Fresh})
	}
	writeJSON(w, 200, out)
}
