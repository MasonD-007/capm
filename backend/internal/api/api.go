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

	"github.com/MasonD-007/capm/backend/internal/store"
	"github.com/MasonD-007/capm/manifest"
)

// Config holds the API's tunable limits. Zero values mean the defaults.
type Config struct {
	MaxBundleBytes int64            // PUT body cap; default 5 MiB (MAX_BUNDLE_BYTES)
	PublishPerHour int              // per authenticated user; default 30 (PUBLISH_RATE_PER_HOUR)
	Now            func() time.Time // injectable clock for the publish limiter
}

// AuthFunc identifies the caller of a write request.
type AuthFunc func(r *http.Request) (id int64, login string, ok bool)

type API struct {
	store        *store.Store
	authenticate AuthFunc
	cfg          Config
	publishLim   *Limiter
}

func New(s *store.Store, auth AuthFunc) *API { return NewWithConfig(s, auth, Config{}) }

func NewWithConfig(s *store.Store, auth AuthFunc, cfg Config) *API {
	if cfg.MaxBundleBytes <= 0 {
		cfg.MaxBundleBytes = 5 << 20
	}
	if cfg.PublishPerHour <= 0 {
		cfg.PublishPerHour = 30
	}
	return &API{store: s, authenticate: auth, cfg: cfg,
		publishLim: NewLimiter(cfg.PublishPerHour, time.Hour, cfg.Now)}
}

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/bundles", a.list)
	mux.HandleFunc("GET /v1/bundles/{owner}/{name}", a.versions)
	mux.HandleFunc("GET /v1/bundles/{owner}/{name}/{version}", a.metadata)
	mux.HandleFunc("GET /v1/bundles/{owner}/{name}/{version}/download", a.download)
	mux.HandleFunc("GET /v1/bundles/{owner}/{name}/resolve", a.resolve)
	mux.HandleFunc("PUT /v1/bundles/{owner}/{name}/{version}", a.publish)
	mux.HandleFunc("POST /v1/bundles/{owner}/{name}/{version}/yank", a.yank(true))
	mux.HandleFunc("DELETE /v1/bundles/{owner}/{name}/{version}/yank", a.yank(false))
	return noTombstones(mux)
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

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func internal(w http.ResponseWriter, err error) {
	log.Printf("internal error: %v", err)
	writeErr(w, http.StatusInternalServerError, "internal error")
}

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
	bs, err := a.store.List(limit, offset)
	if err != nil {
		internal(w, err)
		return
	}
	type item struct {
		Owner      int64  `json:"ownerId"`
		OwnerLogin string `json:"owner"`
		Name       string `json:"name"`
		// Latest is the version `capm run` would resolve (see
		// latestInstallable); empty when every version is yanked.
		Latest string `json:"latest"`
		// Description is that version's author-supplied description
		// (unverified); empty when Latest is.
		Description string `json:"description"`
	}
	out := make([]item, 0, len(bs))
	for _, b := range bs {
		it := item{Owner: b.Owner, OwnerLogin: b.OwnerLogin, Name: b.Name}
		vs, err := a.store.Versions(b.OwnerLogin, b.Name)
		if err != nil {
			internal(w, err)
			return
		}
		if v := latestInstallable(vs); v != nil {
			it.Latest, it.Description = v.Version, v.Manifest.Metadata.Description
		}
		out = append(out, it)
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
		Summary   manifest.Summary  `json:"summary"`
		CreatedAt time.Time         `json:"createdAt"`
	}
	out := make([]item, 0, len(vs))
	for _, v := range vs {
		out = append(out, item{v.Version, v.Digest, v.Yanked, v.Manifest, v.Manifest.EnforcedSummary(), v.CreatedAt})
	}
	writeJSON(w, 200, out)
}

// metadata returns the manifest, summary, digest and yanked flag for one exact
// version, so a client can inspect a bundle without downloading it. Unlike
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
	writeJSON(w, 200, map[string]any{"version": pick.Version, "digest": pick.Digest, "yanked": pick.Yanked, "manifest": pick.Manifest, "summary": pick.Manifest.EnforcedSummary(), "createdAt": pick.CreatedAt})
}

func (a *API) download(w http.ResponseWriter, r *http.Request) {
	b, err := a.store.Blob(r.PathValue("owner"), r.PathValue("name"), r.PathValue("version"))
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
	w.Write(b)
}

func (a *API) publish(w http.ResponseWriter, r *http.Request) {
	id, login, ok := a.authenticate(r)
	if !ok {
		writeErr(w, 401, "authentication required")
		return
	}
	owner, name, version := r.PathValue("owner"), r.PathValue("name"), r.PathValue("version")
	if !strings.EqualFold(owner, login) {
		writeErr(w, 403, "you can only publish under your own login")
		return
	}
	if ok, retry := a.publishLim.Allow(strconv.FormatInt(id, 10)); !ok {
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
	err = a.store.Publish(id, login, name, version, body)
	switch {
	case err == nil:
		writeJSON(w, 201, map[string]string{"owner": login, "name": name, "version": version})
	case errors.Is(err, store.ErrInvalid):
		writeErr(w, 400, err.Error())
	case errors.Is(err, store.ErrVersionExists):
		writeErr(w, 409, "version already exists")
	default:
		internal(w, err)
	}
}

func (a *API) yank(yanked bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, login, ok := a.authenticate(r)
		if !ok {
			writeErr(w, 401, "authentication required")
			return
		}
		if !strings.EqualFold(r.PathValue("owner"), login) {
			writeErr(w, 403, "only the owner can yank or un-yank versions")
			return
		}
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
	}
	out := map[string]any{"version": pick.Version, "digest": pick.Digest, "yanked": pick.Yanked}
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
		if vs[i].Yanked {
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
