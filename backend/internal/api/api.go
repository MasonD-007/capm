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

const maxBody = 32 << 20

// AuthFunc identifies the caller of a write request.
type AuthFunc func(r *http.Request) (id int64, login string, ok bool)

type API struct {
	store        *store.Store
	authenticate AuthFunc
}

func New(s *store.Store, auth AuthFunc) *API { return &API{store: s, authenticate: auth} }

func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/bundles", a.list)
	mux.HandleFunc("GET /v1/bundles/{owner}/{name}", a.versions)
	mux.HandleFunc("GET /v1/bundles/{owner}/{name}/{version}/download", a.download)
	mux.HandleFunc("PUT /v1/bundles/{owner}/{name}/{version}", a.publish)
	return mux
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
	}
	out := make([]item, 0, len(bs))
	for _, b := range bs {
		out = append(out, item{b.Owner, b.OwnerLogin, b.Name})
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
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
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
