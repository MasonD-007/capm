package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MasonD-007/capm/backend/internal/store"
)

// maxReasonLen caps an admin's takedown or ban reason, in characters.
const maxReasonLen = 500

type adminKey struct{}

// adminGate makes everything under /v1/admin/ answer exactly like a route
// that does not exist (the mux's own 404) unless the caller is a configured
// admin, so the surface is not advertised to anyone else, signed in or not.
func (a *API) adminGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p := r.URL.Path; p == "/v1/admin" || strings.HasPrefix(p, "/v1/admin/") {
			id, _, ok := a.authenticate(r)
			if !ok || a.cfg.IsAdmin == nil || !a.cfg.IsAdmin(id) {
				http.NotFound(w, r)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), adminKey{}, id))
		}
		next.ServeHTTP(w, r)
	})
}

func (a *API) mountAdmin(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/admin/bundles/{owner}/{name}/{version}/remove", a.adminRemove(false))
	mux.HandleFunc("DELETE /v1/admin/bundles/{owner}/{name}/{version}/remove", a.adminRestore(false))
	mux.HandleFunc("POST /v1/admin/bundles/{owner}/{name}/remove", a.adminRemove(true))
	mux.HandleFunc("DELETE /v1/admin/bundles/{owner}/{name}/remove", a.adminRestore(true))
	mux.HandleFunc("POST /v1/admin/users/{user}/ban", a.adminBan)
	mux.HandleFunc("DELETE /v1/admin/users/{user}/ban", a.adminUnban)
	mux.HandleFunc("DELETE /v1/admin/users/{user}/tokens", a.adminRevokeTokens)
	mux.HandleFunc("GET /v1/admin/log", a.adminLog)
}

func adminOf(r *http.Request) int64 { id, _ := r.Context().Value(adminKey{}).(int64); return id }

// readReason decodes {"reason": "..."} and validates it, writing the 400.
func readReason(w http.ResponseWriter, r *http.Request) (string, bool) {
	var in struct {
		Reason string `json:"reason"`
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil || json.Unmarshal(b, &in) != nil {
		writeErr(w, 400, `body must be JSON like {"reason": "why"}`)
		return "", false
	}
	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		writeErr(w, 400, "a reason is required")
		return "", false
	}
	if utf8.RuneCountInString(reason) > maxReasonLen {
		writeErr(w, 400, "reason must be at most 500 characters")
		return "", false
	}
	return reason, true
}

func (a *API) adminRemove(whole bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reason, ok := readReason(w, r)
		if !ok {
			return
		}
		owner, name, version := r.PathValue("owner"), r.PathValue("name"), r.PathValue("version")
		var (
			res store.RemoveResult
			err error
		)
		if whole {
			res, err = a.store.RemoveBundle(adminOf(r), owner, name, reason)
		} else {
			res, err = a.store.RemoveVersion(adminOf(r), owner, name, version, reason)
		}
		switch {
		case err == nil:
			writeJSON(w, 200, map[string]any{"owner": owner, "name": name, "removed": true,
				"versions": res.Versions, "blobsDeleted": res.BlobsDeleted})
		case errors.Is(err, store.ErrNotFound):
			writeErr(w, 404, "not found")
		case errors.Is(err, store.ErrAlreadyRemoved):
			writeErr(w, 409, "already removed")
		default:
			internal(w, err)
		}
	}
}

func (a *API) adminRestore(whole bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		owner, name, version := r.PathValue("owner"), r.PathValue("name"), r.PathValue("version")
		var (
			res store.RestoreResult
			err error
		)
		if whole {
			res, err = a.store.RestoreBundle(adminOf(r), owner, name)
		} else {
			err = a.store.RestoreVersion(adminOf(r), owner, name, version)
			res.Restored = []string{version}
		}
		switch {
		case err == nil:
			if res.Skipped == nil {
				res.Skipped = []string{}
			}
			writeJSON(w, 200, map[string]any{"owner": owner, "name": name, "restored": res.Restored, "skipped": res.Skipped})
		case errors.Is(err, store.ErrNotFound):
			writeErr(w, 404, "not found")
		case errors.Is(err, store.ErrNotRemoved):
			writeErr(w, 409, "not removed")
		case errors.Is(err, store.ErrBlobMissing):
			writeErr(w, 409, "cannot restore: the bundle's data was deleted when it was removed. "+
				"Restore the blob file from a backup into the blobs directory, then retry")
		default:
			internal(w, err)
		}
	}
}

// resolveUser accepts a GitHub numeric id (all digits) or a login.
func (a *API) resolveUser(w http.ResponseWriter, s string) (int64, bool) {
	if id, err := strconv.ParseInt(s, 10, 64); err == nil {
		if id <= 0 {
			writeErr(w, 400, "invalid user id")
			return 0, false
		}
		return id, true
	}
	id, err := a.store.UserIDByLogin(s)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, 404, "not found")
		return 0, false
	}
	if err != nil {
		internal(w, err)
		return 0, false
	}
	return id, true
}

func (a *API) adminBan(w http.ResponseWriter, r *http.Request) {
	reason, ok := readReason(w, r)
	if !ok {
		return
	}
	id, ok := a.resolveUser(w, r.PathValue("user"))
	if !ok {
		return
	}
	if a.cfg.IsAdmin(id) {
		writeErr(w, 400, "admins cannot be banned")
		return
	}
	switch err := a.store.BanUser(adminOf(r), id, reason); {
	case err == nil:
		writeJSON(w, 200, map[string]any{"id": id, "banned": true})
	case errors.Is(err, store.ErrAlreadyBanned):
		writeErr(w, 409, "already banned")
	default:
		internal(w, err)
	}
}

func (a *API) adminUnban(w http.ResponseWriter, r *http.Request) {
	id, ok := a.resolveUser(w, r.PathValue("user"))
	if !ok {
		return
	}
	switch err := a.store.UnbanUser(adminOf(r), id); {
	case err == nil:
		writeJSON(w, 200, map[string]any{"id": id, "banned": false})
	case errors.Is(err, store.ErrNotBanned):
		writeErr(w, 404, "user is not banned")
	default:
		internal(w, err)
	}
}

// adminRevokeTokens revokes every token of a user (login or numeric id),
// audited. The user can log in again to get a new one (unlike a ban).
func (a *API) adminRevokeTokens(w http.ResponseWriter, r *http.Request) {
	id, ok := a.resolveUser(w, r.PathValue("user"))
	if !ok {
		return
	}
	n, err := a.store.RevokeAllTokens(adminOf(r), id)
	if err != nil {
		internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "revoked": n})
}

func (a *API) adminLog(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			writeErr(w, 400, "limit must be a positive integer")
			return
		}
		limit = min(n, 500)
	}
	log, err := a.store.AdminLog(limit)
	if err != nil {
		internal(w, err)
		return
	}
	type item struct {
		ID        int64     `json:"id"`
		AdminID   int64     `json:"adminId"`
		Admin     string    `json:"admin"`
		Action    string    `json:"action"`
		Target    string    `json:"target"`
		Reason    string    `json:"reason"`
		CreatedAt time.Time `json:"createdAt"`
	}
	out := make([]item, 0, len(log))
	for _, l := range log {
		out = append(out, item{l.ID, l.AdminID, l.AdminLogin, l.Action, l.Target, l.Reason, l.CreatedAt})
	}
	writeJSON(w, 200, out)
}
