// Package api serves the registry HTTP API.
package api

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MasonD-007/capm/backend/internal/store"
	"github.com/MasonD-007/capm/manifest"
)

// Config holds the API's tunable limits. Zero values mean the defaults.
type Config struct {
	MaxBundleBytes int64            // PUT body cap; default 5 MiB (MAX_BUNDLE_BYTES)
	PublishPerHour int              // per authenticated user; default 30 (PUBLISH_RATE_PER_HOUR)
	Now            func() time.Time // injectable clock for the publish limiter
	// IsAdmin reports whether a GitHub user id may use /v1/admin/. Nil means
	// nobody may.
	IsAdmin func(id int64) bool
	// TrustProxy and ClientIPHeader are TRUSTED_PROXY and CLIENT_IP_HEADER:
	// the same client-IP derivation the auth limiter uses (see clientIP).
	TrustProxy     bool
	ClientIPHeader string
	// ReportPerHour is reports per client IP per hour (default 5).
	// ReportsDisabled (REPORT_RATE_PER_HOUR=0) makes the report route a 404.
	ReportPerHour   int
	ReportsDisabled bool
	// Notifier hears about each newly stored report; nil means none.
	Notifier ReportNotifier
	// ReportSalt keys reporter hashes; nil means a fresh random salt (tests
	// only set it).
	ReportSalt []byte
	// AuthDetail, when set, replaces the AuthFunc passed to New: it resolves
	// the bearer token with its scope and claims (see auth.AuthenticateDetail).
	// Without it every caller is a full-power caller, which is what tests that
	// predate token scopes rely on.
	AuthDetail func(r *http.Request) (store.Token, bool)
}

// AuthFunc identifies the caller of a write request. It must only ever
// return ok for a full-power token (see Config.AuthDetail for scoped ones).
type AuthFunc func(r *http.Request) (id int64, login string, ok bool)

// publishRoute is the one authenticated route a publish-scoped token may call.
const publishRoute = "PUT /v1/bundles/{owner}/{name}/{version}"

// ScopePublish is the scope of tokens minted for CI: publish only.
const ScopePublish = "publish"

type API struct {
	store        *store.Store
	authenticate AuthFunc
	cfg          Config
	publishLim   *Limiter
	reportLim    *Limiter
	reportSalt   []byte
	// countDownload records one successful download; tests replace it.
	countDownload func(owner, name, version string) error
	// authzHook, when set (tests only), hears the route pattern of every call
	// to authorizeOwner.
	authzHook func(pattern string)
}

func New(s *store.Store, auth AuthFunc) *API { return NewWithConfig(s, auth, Config{}) }

func NewWithConfig(s *store.Store, auth AuthFunc, cfg Config) *API {
	if cfg.MaxBundleBytes <= 0 {
		cfg.MaxBundleBytes = 5 << 20
	}
	if cfg.PublishPerHour <= 0 {
		cfg.PublishPerHour = 30
	}
	if cfg.ReportPerHour <= 0 {
		cfg.ReportPerHour = defaultReportPerHour
	}
	salt := cfg.ReportSalt
	if salt == nil {
		salt = newReportSalt()
	}
	return &API{store: s, authenticate: auth, cfg: cfg, reportSalt: salt,
		publishLim: NewLimiter(cfg.PublishPerHour, time.Hour, cfg.Now), countDownload: s.CountDownload,
		reportLim: NewLimiter(cfg.ReportPerHour, time.Hour, cfg.Now)}
}

// register is the single list of routes. Handler mounts them on a mux and
// Routes reports their patterns, so a test that enumerates Routes sees exactly
// what is served.
func (a *API) register(handle func(pattern string, h func(http.ResponseWriter, *http.Request))) {
	handle("GET /v1/bundles", a.list)
	handle("GET /v1/bundles/{owner}/{name}", a.versions)
	handle("GET /v1/bundles/{owner}/{name}/{version}", a.metadata)
	handle("GET /v1/bundles/{owner}/{name}/{version}/download", a.download)
	handle("GET /v1/bundles/{owner}/{name}/resolve", a.resolve)
	handle(publishRoute, a.publish)
	handle("POST /v1/bundles/{owner}/{name}/report", a.report)
	handle("POST /v1/bundles/{owner}/{name}/{version}/yank", a.yank(true))
	handle("DELETE /v1/bundles/{owner}/{name}/{version}/yank", a.yank(false))
	a.mountAdmin(handle)
}

// Routes lists the patterns Handler serves ("METHOD /path").
func (a *API) Routes() []string {
	var out []string
	a.register(func(p string, _ func(http.ResponseWriter, *http.Request)) { out = append(out, p) })
	return out
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	a.register(mux.HandleFunc)
	return a.adminGate(noTombstones(mux))
}

// resolveCaller authenticates r without writing a response.
func (a *API) resolveCaller(r *http.Request) (store.Token, bool) {
	if a.cfg.AuthDetail != nil {
		return a.cfg.AuthDetail(r)
	}
	id, login, ok := a.authenticate(r)
	return store.Token{UserID: id, Login: login}, ok
}

// scopeRefused is the 403 body for a scoped token on a route it may not use.
const scopeRefused = "this token is publish-scoped (issued to a CI workflow) and can only publish bundles under its own login"

// caller authenticates r for a route that needs a signed-in user and writes
// the 401 or 403 itself. Scoped tokens are allow-listed here, in one place:
// a "publish" token passes only on publishRoute, and a token whose scope is
// anything else (including one a future release adds) is refused everywhere.
// Every handler that needs an identity calls this, so a new route is closed to
// scoped tokens by default.
func (a *API) caller(w http.ResponseWriter, r *http.Request) (store.Token, bool) {
	tk, ok := a.resolveCaller(r)
	if !ok {
		writeErr(w, 401, "authentication required")
		return store.Token{}, false
	}
	if tk.Scope != "" && !(tk.Scope == ScopePublish && r.Pattern == publishRoute) {
		writeErr(w, 403, scopeRefused)
		return store.Token{}, false
	}
	return tk, true
}

// optionalCaller identifies r's caller for routes that work anonymously. A
// scoped token is not an identity there: it is treated as anonymous.
func (a *API) optionalCaller(r *http.Request) (store.Token, bool) {
	tk, ok := a.resolveCaller(r)
	if !ok || tk.Scope != "" {
		return store.Token{}, false
	}
	return tk, true
}

// noTombstones makes owners whose login contains "~" (tombstoned ids, see
// store.upsertUser) unaddressable: any /v1/bundles/<owner>/... path with such
// an owner is a 404.
func noTombstones(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rest, ok := strings.CutPrefix(r.URL.Path, "/v1/bundles/"); ok {
			owner, _, _ := strings.Cut(rest, "/")
			if strings.Contains(owner, "~") {
				writeErr(w, 404, "not found")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// writeGone is the 410 for a version an admin removed. "error" reads well in
// older clients that only show that field; "reason" is the admin's text.
func writeGone(w http.ResponseWriter, reason string) {
	writeJSON(w, http.StatusGone, map[string]any{
		"error": "removed by the registry: " + reason, "reason": reason, "removed": true})
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func internal(w http.ResponseWriter, err error) {
	log.Printf("internal error: %v", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

// maxSearchLen caps the q parameter of the list endpoint, in characters.
const maxSearchLen = 100

func (a *API) list(w http.ResponseWriter, r *http.Request) {
	limit, offset := 50, 0
	q := r.URL.Query()
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeErr(w, 400, "limit must be a positive integer")
			return
		}
		limit = min(n, 200)
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeErr(w, 400, "offset must be a non-negative integer")
			return
		}
		offset = n
	}
	owner := q.Get("owner")
	sortBy := q.Get("sort")
	switch sortBy {
	case "":
		sortBy = store.SortName
	case store.SortName, store.SortRecent, store.SortDownloads:
	default:
		writeErr(w, 400, "sort must be one of: name, recent, downloads")
		return
	}
	text := strings.TrimSpace(q.Get("q"))
	if utf8.RuneCountInString(text) > maxSearchLen {
		writeErr(w, 400, "q must be at most 100 characters")
		return
	}
	type item struct {
		Owner      int64  `json:"ownerId"`
		OwnerLogin string `json:"owner"`
		// OwnerKind is "user" or "org".
		OwnerKind string `json:"ownerKind"`
		Name      string `json:"name"`
		// Latest is the version `capm run` would resolve (see
		// latestInstallable); empty when every version is yanked.
		Latest string `json:"latest"`
		// Description is that version's author-supplied description
		// (unverified); empty when Latest is.
		Description string `json:"description"`
		// RiskLabels are computed from that version's manifest
		// (manifest.RiskLabels); [] when Latest is empty. Risk is the highest
		// severity, "" for none. Clients must recompute from the manifest.
		RiskLabels []manifest.RiskLabel `json:"riskLabels"`
		Risk       string               `json:"risk"`
		// Downloads30d is the raw count of download requests for the bundle's
		// non-removed versions over the last 30 UTC days. Anyone can inflate
		// it; it is not a trust or quality signal and never affects search.
		Downloads30d int64 `json:"downloads30d"`
		// UpdatedAt is the newest non-removed version's creation time; absent
		// when the bundle has none.
		UpdatedAt *time.Time `json:"updatedAt,omitempty"`
	}
	// fill adds the latest installable version and its description.
	fill := func(b store.BundleStat) (item, error) {
		it := item{Owner: b.Owner, OwnerLogin: b.OwnerLogin, OwnerKind: b.OwnerKind, Name: b.Name, RiskLabels: []manifest.RiskLabel{}, Downloads30d: b.Downloads30d}
		if !b.UpdatedAt.IsZero() {
			u := b.UpdatedAt
			it.UpdatedAt = &u
		}
		vs, err := a.store.Versions(b.OwnerLogin, b.Name)
		if err != nil {
			return it, err
		}
		if v := latestInstallable(vs); v != nil {
			it.Latest, it.Description = v.Version, v.Manifest.Metadata.Description
			it.RiskLabels = v.Manifest.RiskLabels()
			it.Risk = manifest.HighestSeverity(it.RiskLabels)
		}
		return it, nil
	}
	out := []item{}
	if text == "" {
		bs, err := a.store.ListStats(owner, sortBy, limit, offset)
		if err != nil {
			internal(w, err)
			return
		}
		for _, b := range bs {
			it, err := fill(b)
			if err != nil {
				internal(w, err)
				return
			}
			out = append(out, it)
		}
		writeJSON(w, 200, out)
		return
	}
	// The description lives in each version's manifest, so a search walks the
	// (owner-filtered) bundles in the requested sort order, which the store
	// computes without manifests. Owner and name are checked first; versions
	// are loaded only to check the description of the rest and to build the
	// items on the requested page. Paging applies to matches in that order,
	// and the walk stops once the page is full. Counts decide order only,
	// never whether a bundle matches.
	bs, err := a.store.ListStats(owner, sortBy, -1, 0)
	if err != nil {
		internal(w, err)
		return
	}
	needle := strings.ToLower(text)
	matched := 0
	for _, b := range bs {
		var it item
		filled := false
		hit := strings.Contains(strings.ToLower(b.OwnerLogin), needle) ||
			strings.Contains(strings.ToLower(b.Name), needle)
		if !hit {
			if it, err = fill(b); err != nil {
				internal(w, err)
				return
			}
			filled = true
			hit = strings.Contains(strings.ToLower(it.Description), needle)
		}
		if !hit {
			continue
		}
		if matched++; matched <= offset {
			continue
		}
		if !filled {
			if it, err = fill(b); err != nil {
				internal(w, err)
				return
			}
		}
		out = append(out, it)
		if len(out) == limit {
			break
		}
	}
	writeJSON(w, 200, out)
}

func (a *API) versions(w http.ResponseWriter, r *http.Request) {
	vs, err := a.store.Versions(r.PathValue("owner"), r.PathValue("name"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, 404, "bundle not found")
		return
	}
	if err != nil {
		internal(w, err)
		return
	}
	type item struct {
		Version   string            `json:"version"`
		Digest    string            `json:"digest"`
		Yanked    bool              `json:"yanked"`
		Manifest  manifest.Manifest `json:"manifest"`
		OwnerKind string            `json:"ownerKind"`
		// PublishedBy is the login of the member who published a version of
		// an organisation's bundle; absent for a user's own namespace.
		PublishedBy string           `json:"publishedBy,omitempty"`
		Summary     manifest.Summary `json:"summary"`
		CreatedAt   time.Time        `json:"createdAt"`
		// Removed versions stay listed (their number can never be reused)
		// but their manifest is withheld: a takedown may be about its content.
		Removed       bool   `json:"removed"`
		RemovedReason string `json:"removedReason"`
		// Raw request counts (see the list's downloads30d); 0 for a removed
		// version, whose history is kept but not shown.
		Downloads    int64 `json:"downloads"`
		Downloads30d int64 `json:"downloads30d"`
		// PublishedVia is recorded provenance from the CI token that
		// published the version (repository, workflow ref, commit); absent
		// for every other version. It is not a verified-publisher mark.
		PublishedVia map[string]string `json:"publishedVia,omitempty"`
	}
	dl, err := a.store.VersionDownloads(r.PathValue("owner"), r.PathValue("name"))
	if err != nil {
		internal(w, err)
		return
	}
	out := make([]item, 0, len(vs))
	for _, v := range vs {
		m := v.Manifest
		if v.Removed {
			m = manifest.Manifest{}
		}
		out = append(out, item{Version: v.Version, Digest: v.Digest, Yanked: v.Yanked, Manifest: m, OwnerKind: v.OwnerKind, PublishedBy: v.PublishedBy, Summary: m.EnforcedSummary(), CreatedAt: v.CreatedAt, Removed: v.Removed, RemovedReason: v.RemovedReason, Downloads: dl[v.Version].Total, Downloads30d: dl[v.Version].Last30d, PublishedVia: publishedVia(v.PublishedVia)})
	}
	writeJSON(w, 200, out)
}

// metadata returns the manifest, summary, digest, yanked flag and (when the
// bundle has one) README text for one exact version, so a client can inspect a bundle without downloading it. Unlike
// /resolve it does not accept "latest"; callers resolve a version first.
func (a *API) metadata(w http.ResponseWriter, r *http.Request) {
	vs, err := a.store.Versions(r.PathValue("owner"), r.PathValue("name"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, 404, "bundle not found")
		return
	}
	if err != nil {
		internal(w, err)
		return
	}
	var pick *store.Version
	for i := range vs {
		if vs[i].Version == r.PathValue("version") {
			pick = &vs[i]
		}
	}
	if pick == nil {
		writeErr(w, 404, "version not found")
		return
	}
	if pick.Removed {
		writeGone(w, pick.RemovedReason)
		return
	}
	out := map[string]any{"ownerId": pick.OwnerID, "ownerKind": pick.OwnerKind, "version": pick.Version, "digest": pick.Digest, "yanked": pick.Yanked, "manifest": pick.Manifest, "summary": pick.Manifest.EnforcedSummary(), "riskLabels": pick.Manifest.RiskLabels(), "createdAt": pick.CreatedAt}
	// Raw request counts for this version (not a trust signal).
	dl, err := a.store.VersionDownloads(r.PathValue("owner"), r.PathValue("name"))
	if err != nil {
		internal(w, err)
		return
	}
	out["downloads"], out["downloads30d"] = dl[pick.Version].Total, dl[pick.Version].Last30d
	if pv := publishedVia(pick.PublishedVia); pv != nil {
		out["publishedVia"] = pv
	}
	if pick.PublishedBy != "" {
		out["publishedBy"] = pick.PublishedBy
	}
	// The README is author-supplied, unverified text. It is only on this
	// per-version endpoint (never in lists, for size) and omitted when empty.
	readme, err := a.store.Readme(r.PathValue("owner"), r.PathValue("name"), pick.Version)
	if err != nil {
		internal(w, err)
		return
	}
	if readme != "" {
		out["readme"] = readme
	}
	writeJSON(w, 200, out)
}

func (a *API) download(w http.ResponseWriter, r *http.Request) {
	b, err := a.store.Blob(r.PathValue("owner"), r.PathValue("name"), r.PathValue("version"))
	var re *store.RemovedError
	if errors.As(err, &re) {
		writeGone(w, re.Reason)
		return
	}
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, 404, "version not found")
		return
	}
	if err != nil {
		internal(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	n, err := w.Write(b)
	// Count only a download that was actually served: HEAD requests (the
	// route answers them through this handler) carry no body, and a write
	// error means the client did not get the file. A failure to count is
	// logged and never fails the download.
	if r.Method == http.MethodHead || err != nil || n != len(b) {
		return
	}
	if err := a.countDownload(r.PathValue("owner"), r.PathValue("name"), r.PathValue("version")); err != nil {
		log.Printf("count download %s/%s@%s: %v", r.PathValue("owner"), r.PathValue("name"), r.PathValue("version"), err)
	}
}

func (a *API) publish(w http.ResponseWriter, r *http.Request) {
	tk, ok := a.caller(w, r)
	if !ok {
		return
	}
	owner, name, version := r.PathValue("owner"), r.PathValue("name"), r.PathValue("version")
	acc, ok := a.authorizeOwner(w, r, tk, owner, actPublish)
	if !ok {
		return
	}
	id, login := acc.Owner.ID, acc.Owner.Login
	if ok, retry := a.publishLim.Allow(strconv.FormatInt(tk.UserID, 10)); !ok {
		tooMany(w, retry)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, a.cfg.MaxBundleBytes))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, 413, "bundle too large")
		} else {
			writeErr(w, 400, "could not read body")
		}
		return
	}
	// A publish rejected by a quota still counts against the hourly allowance
	// (Allow above already recorded it). Refunding it would let a user parked
	// at their limit upload and have unpacked 5 MiB bodies without bound.
	err = a.store.PublishAs(id, login, name, version, body, store.PublishMeta{Via: viaRecord(tk), PublishedBy: acc.PublishedBy})
	var qe *store.QuotaError
	switch {
	case err == nil:
		writeJSON(w, 201, map[string]string{"owner": login, "name": name, "version": version})
	case errors.Is(err, store.ErrInvalid):
		writeErr(w, 400, err.Error())
	case errors.Is(err, store.ErrVersionExists):
		writeErr(w, 409, "version already exists")
	case errors.As(err, &qe) && qe.Limit == store.LimitTotalBytes:
		// The registry's own numbers are not the publisher's business.
		writeJSON(w, http.StatusInsufficientStorage, map[string]any{"error": qe.Error(), "limit": qe.Limit})
	case errors.As(err, &qe):
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"error": qe.Error(), "limit": qe.Limit, "used": qe.Used, "max": qe.Max})
	default:
		internal(w, err)
	}
}

func (a *API) yank(yanked bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tk, ok := a.caller(w, r)
		if !ok {
			return
		}
		acc, ok := a.authorizeOwner(w, r, tk, r.PathValue("owner"), actYank)
		if !ok {
			return
		}
		id, login := acc.Owner.ID, acc.Owner.Login
		name, version := r.PathValue("name"), r.PathValue("version")
		err := a.store.SetYanked(id, name, version, yanked)
		switch {
		case err == nil:
			writeJSON(w, 200, map[string]any{"owner": login, "name": name, "version": version, "yanked": yanked})
		case errors.Is(err, store.ErrNotFound):
			writeErr(w, 404, "version not found")
		default:
			internal(w, err)
		}
	}
}

// viaRecord is the compact JSON provenance stored with a version published by
// a CI token ("" for any other token): only these claims, only strings,
// taken from the claims recorded when the token was minted from a verified ID
// token. It is recorded provenance, not an endorsement.
func viaRecord(tk store.Token) string {
	if tk.Scope != ScopePublish || tk.Claims == "" {
		return ""
	}
	var claims map[string]string
	if json.Unmarshal([]byte(tk.Claims), &claims) != nil {
		return ""
	}
	rec := map[string]string{}
	for _, k := range []string{"repository", "repository_id", "workflow_ref", "sha", "run_id"} {
		if v := claims[k]; v != "" {
			rec[k] = v
		}
	}
	if len(rec) == 0 {
		return ""
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return ""
	}
	return string(b)
}

// publishedVia renders a stored provenance record for the API, or nil when
// the version was not published with a CI token.
func publishedVia(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	var rec map[string]string
	if json.Unmarshal([]byte(raw), &rec) != nil {
		return nil
	}
	return map[string]string{"repository": rec["repository"], "workflowRef": rec["workflow_ref"], "sha": rec["sha"]}
}

// resolve picks a version: range=latest (the default) is the highest semver
// among non-yanked versions, preferring releases over prereleases; any other
// value is an exact version, which resolves even if yanked (with a warning).
func (a *API) resolve(w http.ResponseWriter, r *http.Request) {
	rng := r.URL.Query().Get("range")
	if rng == "" {
		rng = "latest"
	}
	vs, err := a.store.Versions(r.PathValue("owner"), r.PathValue("name"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, 404, "bundle not found")
		return
	}
	if err != nil {
		internal(w, err)
		return
	}
	var pick *store.Version
	if rng == "latest" {
		pick = latestInstallable(vs)
		if pick == nil {
			// If a takedown is why nothing is installable, say so (the
			// newest removed version's reason) instead of a bare 404.
			for i := len(vs) - 1; i >= 0; i-- {
				if vs[i].Removed {
					writeGone(w, vs[i].RemovedReason)
					return
				}
			}
			writeErr(w, 404, "no installable version: every version of this bundle is yanked")
			return
		}
	} else {
		for i := range vs {
			if vs[i].Version == rng {
				pick = &vs[i]
			}
		}
		if pick == nil {
			writeErr(w, 404, "version not found")
			return
		}
		if pick.Removed {
			writeGone(w, pick.RemovedReason)
			return
		}
	}
	out := map[string]any{"ownerId": pick.OwnerID, "ownerKind": pick.OwnerKind, "version": pick.Version, "digest": pick.Digest, "yanked": pick.Yanked}
	if pick.Yanked {
		out["warning"] = "yanked"
	}
	writeJSON(w, 200, out)
}

// latestInstallable is the highest semver among non-yanked versions,
// preferring releases over prereleases; nil if none. Shared by /resolve and
// the list so both agree on what "latest" means.
func latestInstallable(vs []store.Version) *store.Version {
	var best, bestPre *semver
	var bv, bpv *store.Version
	for i := range vs {
		if vs[i].Yanked || vs[i].Removed {
			continue
		}
		sv, ok := parseSemver(vs[i].Version)
		if !ok {
			continue
		}
		if len(sv.pre) == 0 {
			if best == nil || sv.compare(*best) > 0 {
				best, bv = &sv, &vs[i]
			}
		} else if bestPre == nil || sv.compare(*bestPre) > 0 {
			bestPre, bpv = &sv, &vs[i]
		}
	}
	if bv != nil {
		return bv
	}
	return bpv
}
