package store

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"
)

// Reports are unauthenticated, internet-facing input, so the table is bounded.
const (
	// MaxOpenReportsPerBundle is the most open (unresolved) reports kept for
	// one bundle. Beyond it new reports are accepted and dropped, so one
	// attacker (or a brigade) cannot make a single bundle's backlog grow
	// without bound or bury the admin in it.
	MaxOpenReportsPerBundle = 200
	// MaxOpenReports is the same limit over the whole registry, so spraying
	// reports across many bundles cannot grow the table without bound either.
	MaxOpenReports = 5000

	// dedupWindow is how long an identical open report from the same
	// reporter_key is treated as the same report.
	dedupWindow = 24 * time.Hour
)

var (
	// ErrUnknownVersion means a report named a version the bundle does not
	// have.
	ErrUnknownVersion  = errors.New("store: no such version")
	ErrAlreadyResolved = errors.New("store: report already resolved")
)

// Report states for ListReports.
const (
	ReportsOpen     = "open"
	ReportsResolved = "resolved"
	ReportsAll      = "all"
)

// ReportInput is one submitted report. Reason and Details are validated by the
// caller; ReporterKey is never an address (see the reports table).
type ReportInput struct {
	OwnerLogin, Name string
	Version          string // "" = the whole bundle
	Reason, Details  string
	ReporterUserID   int64 // 0 = anonymous
	ReporterKey      []byte
}

type ReportOutcome int

const (
	// ReportStored: a new row was inserted.
	ReportStored ReportOutcome = iota + 1
	// ReportDuplicate: an identical open report from this reporter within the
	// last 24 hours exists; nothing was inserted (ID is that report's).
	ReportDuplicate
	// ReportDropped: a cap was reached; nothing was inserted.
	ReportDropped
)

type ReportResult struct {
	Outcome    ReportOutcome
	ID         int64  // 0 when Dropped
	OwnerLogin string // canonical (current) owner login
}

// SetReportCaps replaces the open-report caps; tests call it.
func (s *Store) SetReportCaps(perBundle, global int) {
	s.reportCapBundle, s.reportCapGlobal = perBundle, global
}

// AddReport stores a report. ErrNotFound if the bundle does not exist or its
// owner is banned (it answers like any bundle that is not there);
// ErrUnknownVersion if a version is named that the bundle never had. Removed
// and yanked versions are accepted. The checks and the insert are one
// transaction on the store's single connection, so the caps hold exactly
// under concurrency.
func (s *Store) AddReport(in ReportInput) (ReportResult, error) {
	var res ReportResult
	tx, err := s.db.Begin()
	if err != nil {
		return res, err
	}
	defer tx.Rollback()

	var owner int64
	err = tx.QueryRow(`SELECT u.id, u.login FROM users u
		WHERE u.login = ? AND u.login NOT LIKE '~%'
		AND NOT EXISTS (SELECT 1 FROM banned_users bu WHERE bu.user_id = u.id)`, in.OwnerLogin).Scan(&owner, &res.OwnerLogin)
	if errors.Is(err, sql.ErrNoRows) {
		return res, ErrNotFound
	}
	if err != nil {
		return res, err
	}
	var n int
	if err := tx.QueryRow(`SELECT count(*) FROM versions WHERE owner_id = ? AND name = ?`, owner, in.Name).Scan(&n); err != nil {
		return res, err
	}
	if n == 0 {
		return res, ErrNotFound
	}
	if in.Version != "" {
		if err := tx.QueryRow(`SELECT count(*) FROM versions WHERE owner_id = ? AND name = ? AND version = ?`,
			owner, in.Name, in.Version).Scan(&n); err != nil {
			return res, err
		}
		if n == 0 {
			return res, ErrUnknownVersion
		}
	}

	now := s.now()
	var dup int64
	err = tx.QueryRow(`SELECT id FROM reports WHERE owner_id = ? AND name = ? AND reporter_key = ?
		AND version = ? AND reason = ? AND resolved_at IS NULL AND created_at > ? ORDER BY id LIMIT 1`,
		owner, in.Name, in.ReporterKey, in.Version, in.Reason, now.Add(-dedupWindow).Unix()).Scan(&dup)
	if err == nil {
		res.Outcome, res.ID = ReportDuplicate, dup
		return res, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return res, err
	}

	var bundleOpen, allOpen int
	if err := tx.QueryRow(`SELECT count(*) FROM reports WHERE owner_id = ? AND name = ? AND resolved_at IS NULL`,
		owner, in.Name).Scan(&bundleOpen); err != nil {
		return res, err
	}
	if err := tx.QueryRow(`SELECT count(*) FROM reports WHERE resolved_at IS NULL`).Scan(&allOpen); err != nil {
		return res, err
	}
	if bundleOpen >= s.reportCapBundle || allOpen >= s.reportCapGlobal {
		log.Printf("WARN: reports: open-report cap reached (%d for %s/%s of %d; %d of %d overall); dropping a report",
			bundleOpen, res.OwnerLogin, in.Name, s.reportCapBundle, allOpen, s.reportCapGlobal)
		res.Outcome = ReportDropped
		return res, nil
	}

	var reporter any
	if in.ReporterUserID != 0 {
		reporter = in.ReporterUserID
	}
	r, err := tx.Exec(`INSERT INTO reports(owner_id, name, version, reason, details, reporter_user_id, reporter_key, created_at)
		VALUES(?,?,?,?,?,?,?,?)`, owner, in.Name, in.Version, in.Reason, in.Details, reporter, in.ReporterKey, now.Unix())
	if err != nil {
		return res, err
	}
	if res.ID, err = r.LastInsertId(); err != nil {
		return res, err
	}
	if err := tx.Commit(); err != nil {
		return ReportResult{}, err
	}
	res.Outcome = ReportStored
	return res, nil
}

// Report is a stored report as the admin sees it. It never carries
// reporter_key. Strings are attacker-controlled free text.
type Report struct {
	ID         int64
	OwnerID    int64
	OwnerLogin string
	Name       string
	Version    string
	Reason     string
	Details    string
	// ReporterID is the logged-in reporter's user id, 0 for anonymous;
	// ReporterLogin is their current login ("" if unknown).
	ReporterID    int64
	ReporterLogin string
	CreatedAt     time.Time
	// ResolvedAt is the zero time while the report is open.
	ResolvedAt    time.Time
	ResolvedBy    int64
	ResolverLogin string
	Resolution    string
	// BundleState is what has already happened to the reported thing: "live",
	// "removed" (every version it covers is removed) or "owner-banned".
	BundleState string
}

func (r Report) Resolved() bool { return !r.ResolvedAt.IsZero() }

const reportSelect = `SELECT r.id, r.owner_id, COALESCE(o.login, ''), r.name, r.version, r.reason, r.details,
	COALESCE(r.reporter_user_id, 0), COALESCE(ru.login, ''), r.created_at,
	COALESCE(r.resolved_at, 0), COALESCE(r.resolved_by, 0), COALESCE(rb.login, ''), r.resolution,
	CASE WHEN EXISTS (SELECT 1 FROM banned_users bu WHERE bu.user_id = r.owner_id) THEN 'owner-banned'
	     WHEN NOT EXISTS (SELECT 1 FROM versions v WHERE v.owner_id = r.owner_id AND v.name = r.name
	                      AND (r.version = '' OR v.version = r.version) AND v.removed = 0) THEN 'removed'
	     ELSE 'live' END
	FROM reports r
	LEFT JOIN users o ON o.id = r.owner_id
	LEFT JOIN users ru ON ru.id = r.reporter_user_id
	LEFT JOIN users rb ON rb.id = r.resolved_by`

func scanReport(sc interface{ Scan(...any) error }) (Report, error) {
	var r Report
	var created, resolved int64
	err := sc.Scan(&r.ID, &r.OwnerID, &r.OwnerLogin, &r.Name, &r.Version, &r.Reason, &r.Details,
		&r.ReporterID, &r.ReporterLogin, &created, &resolved, &r.ResolvedBy, &r.ResolverLogin, &r.Resolution, &r.BundleState)
	r.CreatedAt = time.Unix(created, 0).UTC()
	if resolved != 0 {
		r.ResolvedAt = time.Unix(resolved, 0).UTC()
	}
	return r, err
}

// ListReports returns reports of the given state (ReportsOpen, ReportsResolved
// or ReportsAll), newest first.
func (s *Store) ListReports(state string, limit, offset int) ([]Report, error) {
	where := ""
	switch state {
	case ReportsOpen:
		where = ` WHERE r.resolved_at IS NULL`
	case ReportsResolved:
		where = ` WHERE r.resolved_at IS NOT NULL`
	case ReportsAll:
	default:
		return nil, fmt.Errorf("store: unknown report state %q", state)
	}
	rows, err := s.db.Query(reportSelect+where+` ORDER BY r.created_at DESC, r.id DESC LIMIT ? OFFSET ?`, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Report{}
	for rows.Next() {
		r, err := scanReport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetReport returns one report, or ErrNotFound.
func (s *Store) GetReport(id int64) (Report, error) {
	r, err := scanReport(s.db.QueryRow(reportSelect+` WHERE r.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Report{}, ErrNotFound
	}
	return r, err
}

// ResolveReport marks a report handled, with the admin's note, and writes the
// audit row in the same transaction. ErrNotFound for an unknown id,
// ErrAlreadyResolved if it was resolved before.
func (s *Store) ResolveReport(adminID, id int64, resolution string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE reports SET resolved_at = ?, resolved_by = ?, resolution = ?
		WHERE id = ? AND resolved_at IS NULL`, s.now().Unix(), adminID, resolution, id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		var one int
		if err := tx.QueryRow(`SELECT 1 FROM reports WHERE id = ?`, id).Scan(&one); errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		return ErrAlreadyResolved
	}
	if err := audit(tx, adminID, "resolve_report", fmt.Sprintf("report:%d", id), resolution); err != nil {
		return err
	}
	return tx.Commit()
}
