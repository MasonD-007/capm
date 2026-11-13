package api

import (
	"bytes"
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

// reportItem is the admin view of a report. It never carries reporter_key.
// Every string is attacker-controlled (details especially); clients must
// sanitise before showing it.
type reportItem struct {
	ID               int64      `json:"id"`
	Owner            string     `json:"owner"`
	Name             string     `json:"name"`
	Version          string     `json:"version"`
	Reason           string     `json:"reason"`
	Details          string     `json:"details"`
	ReporterLoggedIn bool       `json:"reporterLoggedIn"`
	Reporter         string     `json:"reporter,omitempty"`
	CreatedAt        time.Time  `json:"createdAt"`
	ResolvedAt       *time.Time `json:"resolvedAt,omitempty"`
	ResolvedBy       string     `json:"resolvedBy,omitempty"`
	Resolution       string     `json:"resolution,omitempty"`
	// BundleState is "live", "removed" or "owner-banned": what has already
	// been done about the reported bundle. Reports are never auto-resolved.
	BundleState string `json:"bundleState"`
}

func toReportItem(r store.Report) reportItem {
	it := reportItem{ID: r.ID, Owner: r.OwnerLogin, Name: r.Name, Version: r.Version, Reason: r.Reason,
		Details: r.Details, ReporterLoggedIn: r.ReporterID != 0, Reporter: r.ReporterLogin,
		CreatedAt: r.CreatedAt, BundleState: r.BundleState}
	if r.Resolved() {
		t := r.ResolvedAt
		it.ResolvedAt, it.ResolvedBy, it.Resolution = &t, r.ResolverLogin, r.Resolution
		if it.ResolvedBy == "" {
			it.ResolvedBy = strconv.FormatInt(r.ResolvedBy, 10)
		}
	}
	return it
}

func (a *API) adminListReports(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	switch state {
	case "":
		state = store.ReportsOpen
	case store.ReportsOpen, store.ReportsResolved, store.ReportsAll:
	default:
		writeErr(w, 400, "state must be one of: open, resolved, all")
		return
	}
	limit, offset := 50, 0
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
	rs, err := a.store.ListReports(state, limit, offset)
	if err != nil {
		internal(w, err)
		return
	}
	out := make([]reportItem, 0, len(rs))
	for _, r := range rs {
		out = append(out, toReportItem(r))
	}
	writeJSON(w, 200, out)
}

func (a *API) adminGetReport(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeErr(w, 404, "not found")
		return
	}
	rep, err := a.store.GetReport(id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, 404, "not found")
		return
	}
	if err != nil {
		internal(w, err)
		return
	}
	writeJSON(w, 200, toReportItem(rep))
}

func (a *API) adminResolveReport(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeErr(w, 404, "not found")
		return
	}
	var in struct {
		Resolution string `json:"resolution"`
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err != nil || dec.Decode(&in) != nil {
		writeErr(w, 400, `body must be JSON like {"resolution": "what was done"}`)
		return
	}
	res := strings.TrimSpace(in.Resolution)
	if res == "" {
		writeErr(w, 400, "a resolution note is required")
		return
	}
	if utf8.RuneCountInString(res) > maxReasonLen {
		writeErr(w, 400, "resolution must be at most 500 characters")
		return
	}
	switch err := a.store.ResolveReport(adminOf(r), id, res); {
	case err == nil:
		writeJSON(w, 200, map[string]any{"id": id, "resolved": true})
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, 404, "not found")
	case errors.Is(err, store.ErrAlreadyResolved):
		writeErr(w, 409, "already resolved")
	default:
		internal(w, err)
	}
}
