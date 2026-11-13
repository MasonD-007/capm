package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/MasonD-007/capm/backend/internal/store"
)

const (
	// maxReportBody caps the request body. 2000 four-byte characters plus the
	// JSON around them is about 8.1 KB, which fits; anything larger is 413.
	maxReportBody = 8 << 10
	// maxReportDetails caps details, in characters, after sanitising.
	maxReportDetails = 2000
	maxVersionLen    = 128
	// defaultReportPerHour is reports per client IP per hour when
	// REPORT_RATE_PER_HOUR is unset.
	defaultReportPerHour = 5
)

// reportReasons are the accepted values of "reason".
var reportReasons = map[string]bool{"malware": true, "secrets-exposed": true, "impersonation": true, "other": true}

const reasonList = "malware, secrets-exposed, impersonation, other"

// newReportSalt is the per-process secret behind reporter keys. It lives only
// in memory: a restart changes every key, so keys cannot be correlated across
// restarts (or by anyone who gets the database without the process).
func newReportSalt() []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("api: no randomness for the report salt: " + err.Error())
	}
	return b
}

// reporterKey is HMAC-SHA256(salt, ip). The raw IP is never stored.
func reporterKey(salt []byte, ip string) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write([]byte(ip))
	return m.Sum(nil)
}

// cleanDetails trims s and removes control characters other than newline and
// tab (including CR, ESC and DEL, so terminal escape sequences lose their
// introducer), bidirectional override/isolate characters, zero-width space,
// BOM and the Unicode line/paragraph separators.
func cleanDetails(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case unicode.IsControl(r):
		case r == 0x061c, r == 0x200b, r == 0x200e, r == 0x200f, r == 0x2028, r == 0x2029, r == 0xfeff,
			r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
		default:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// report accepts an abuse report. The endpoint is unauthenticated and
// internet-facing, so every input is treated as hostile: bounded body, strict
// JSON, enumerated reason, sanitised bounded details, per-IP rate limit, and
// bounded storage. A valid token is used only to record who reported;
// anything else (no token, bad token) is anonymous, never an error.
//
// Success is always 202 with {}: no id (ids are sequential and would tell any
// caller how many reports exist), and a stored report, a duplicate and a
// capped drop are indistinguishable, so the response cannot be used to learn
// whether other reports exist for a bundle or whether a cap was hit.
func (a *API) report(w http.ResponseWriter, r *http.Request) {
	if a.cfg.ReportsDisabled {
		writeErr(w, 404, "not found")
		return
	}
	ip := clientIP(r, a.cfg.TrustProxy, a.cfg.ClientIPHeader)
	if ok, retry := a.reportLim.Allow(ip); !ok {
		tooMany(w, retry)
		return
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeErr(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxReportBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, 413, "report too large")
		} else {
			writeErr(w, 400, "could not read body")
		}
		return
	}
	var in struct {
		Version string `json:"version"`
		Reason  string `json:"reason"`
		Details string `json:"details"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if !utf8.Valid(body) || dec.Decode(&in) != nil {
		writeErr(w, 400, `body must be JSON like {"version": "", "reason": "malware", "details": "..."}`)
		return
	}
	if _, err := dec.Token(); err != io.EOF {
		writeErr(w, 400, "body must be a single JSON object")
		return
	}
	if !reportReasons[in.Reason] {
		writeErr(w, 400, "reason must be one of: "+reasonList)
		return
	}
	details := cleanDetails(in.Details)
	if utf8.RuneCountInString(details) > maxReportDetails {
		writeErr(w, 400, "details must be at most 2000 characters")
		return
	}
	if details == "" && in.Reason == "other" {
		writeErr(w, 400, `details are required when reason is "other"`)
		return
	}
	if len(in.Version) > maxVersionLen {
		writeErr(w, 400, "version: this bundle has no such version")
		return
	}

	var reporter int64
	if tk, ok := a.optionalCaller(r); ok {
		reporter = tk.UserID
	}
	owner, name := r.PathValue("owner"), r.PathValue("name")
	res, err := a.store.AddReport(store.ReportInput{
		OwnerLogin: owner, Name: name, Version: in.Version, Reason: in.Reason, Details: details,
		ReporterUserID: reporter, ReporterKey: reporterKey(a.reportSalt, ip),
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, 404, "bundle not found")
		return
	case errors.Is(err, store.ErrUnknownVersion):
		writeErr(w, 400, "version: this bundle has no such version")
		return
	case err != nil:
		internal(w, err)
		return
	}
	if res.Outcome == store.ReportStored && a.cfg.Notifier != nil {
		a.cfg.Notifier.Notify(ReportEvent{ID: res.ID, Owner: res.OwnerLogin, Name: name,
			Version: in.Version, Reason: in.Reason, Details: details})
	}
	writeJSON(w, http.StatusAccepted, struct{}{})
}
