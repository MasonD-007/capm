package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/MasonD-007/capm/backend/internal/store"
)

// quotaJSON is the shape of both admin quota routes: the user's usage and
// effective limits (0 = unlimited) and whether each limit is an override.
func quotaJSON(id int64, u store.Usage) map[string]any {
	return map[string]any{"id": id, "bytes": u.Bytes, "maxBytes": u.MaxBytes,
		"bundles": u.Bundles, "maxBundles": u.MaxBundles, "maxBundleVersions": u.MaxBundleVersions,
		"bytesOverridden": u.BytesOverridden, "bundlesOverridden": u.BundlesOverridden}
}

func (a *API) adminGetQuota(w http.ResponseWriter, r *http.Request) {
	id, ok := a.resolveUser(w, r.PathValue("user"))
	if !ok {
		return
	}
	u, err := a.store.Usage(id)
	if err != nil {
		internal(w, err)
		return
	}
	writeJSON(w, 200, quotaJSON(id, u))
}

// maxQuotaValue bounds an override so it stays a sane integer (1 PiB).
const maxQuotaValue = 1 << 50

// parseLimit reads one override value: JSON null (clear) or a whole number
// from 0 (unlimited) to maxQuotaValue. ok is false for anything else,
// including a missing key.
func parseLimit(raw json.RawMessage) (v *int64, ok bool) {
	if len(raw) == 0 {
		return nil, false
	}
	if string(raw) == "null" {
		return nil, true
	}
	var n int64
	if err := json.Unmarshal(raw, &n); err != nil || n < 0 || n > maxQuotaValue {
		return nil, false
	}
	return &n, true
}

// adminSetQuota replaces a user's overrides. Both keys are required so a typo
// cannot silently clear an override; null clears one.
func (a *API) adminSetQuota(w http.ResponseWriter, r *http.Request) {
	const usage = `body must be JSON like {"maxBytes": 524288000, "maxBundles": null} (null clears an override; 0 means unlimited)`
	var in struct {
		MaxBytes   json.RawMessage `json:"maxBytes"`
		MaxBundles json.RawMessage `json:"maxBundles"`
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil || json.Unmarshal(body, &in) != nil {
		writeErr(w, 400, usage)
		return
	}
	maxBytes, ok1 := parseLimit(in.MaxBytes)
	maxBundles, ok2 := parseLimit(in.MaxBundles)
	if !ok1 || !ok2 {
		writeErr(w, 400, usage)
		return
	}
	id, ok := a.resolveUser(w, r.PathValue("user"))
	if !ok {
		return
	}
	if err := a.store.SetQuotaOverride(adminOf(r), id, maxBytes, maxBundles); err != nil {
		internal(w, err)
		return
	}
	u, err := a.store.Usage(id)
	if err != nil {
		internal(w, err)
		return
	}
	writeJSON(w, 200, quotaJSON(id, u))
}
