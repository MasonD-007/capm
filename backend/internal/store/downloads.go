package store

import (
	"database/sql"
	"errors"
	"log"
	"time"
)

// Download counts are raw, unauthenticated request counts: anyone can inflate
// them, they say nothing about trust or quality, and nothing but a day number
// and a count is stored (no address, token or user).
const (
	// dayBeforeWindow is the sentinel day of the rollup row that holds every
	// download older than retentionDays. It is never a real day (day 0 is
	// 1970-01-01), so daily rows are exactly those with day > dayBeforeWindow.
	dayBeforeWindow = 0
	// retentionDays is how long per-day rows are kept before the startup
	// rollup folds them into the sentinel row.
	retentionDays = 400
	// windowDays is the "recent downloads" window, today (UTC) included.
	windowDays = 30
)

// Sort orders for ListStats.
const (
	SortName      = "name"
	SortRecent    = "recent"
	SortDownloads = "downloads"
)

// SetClock replaces the clock that stamps publishes and download days; tests
// call it before using the store.
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// dayNumber is days since the Unix epoch, UTC.
func dayNumber(t time.Time) int64 { return t.Unix() / 86400 }

// windowStart is the first day inside the 30-day window ending today.
func (s *Store) windowStart() int64 { return dayNumber(s.now()) - (windowDays - 1) }

// CountDownload adds one to today's counter for a version that exists, is not
// removed and whose owner is not banned (the same versions Blob serves);
// otherwise ErrNotFound and nothing is stored. It is one upsert statement on
// the store's single connection, so concurrent calls never lose an increment.
func (s *Store) CountDownload(ownerLogin, name, version string) error {
	res, err := s.db.Exec(`INSERT INTO downloads(owner_id, name, version, day, count)
		SELECT v.owner_id, v.name, v.version, ?, 1 FROM versions v JOIN users u ON u.id = v.owner_id
		WHERE u.login = ? AND v.name = ? AND v.version = ? AND v.removed = 0`+notBanned+`
		ON CONFLICT(owner_id, name, version, day) DO UPDATE SET count = count + 1`,
		dayNumber(s.now()), ownerLogin, name, version)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// DownloadCounts are one version's raw request counts: all time (including
// the rolled-up history) and the last 30 UTC days.
type DownloadCounts struct{ Total, Last30d int64 }

// VersionDownloads returns the counts of every non-removed version of a
// bundle that has any, keyed by version. Removed versions are left out (their
// history stays in the table). ErrNotFound for a banned owner, like Versions.
func (s *Store) VersionDownloads(ownerLogin, name string) (map[string]DownloadCounts, error) {
	var owner int64
	err := s.db.QueryRow(`SELECT u.id FROM users u WHERE u.login = ?
		AND NOT EXISTS (SELECT 1 FROM banned_users bu WHERE bu.user_id = u.id)`, ownerLogin).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT d.version, SUM(d.count), COALESCE(SUM(CASE WHEN d.day >= ? THEN d.count END), 0)
		FROM downloads d JOIN versions v ON v.owner_id = d.owner_id AND v.name = d.name AND v.version = d.version
		WHERE d.owner_id = ? AND d.name = ? AND v.removed = 0 GROUP BY d.version`, s.windowStart(), owner, name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]DownloadCounts{}
	for rows.Next() {
		var v string
		var c DownloadCounts
		if err := rows.Scan(&v, &c.Total, &c.Last30d); err != nil {
			return nil, err
		}
		out[v] = c
	}
	return out, rows.Err()
}

// BundleStat is a listed bundle with the two figures the list can sort by.
type BundleStat struct {
	Bundle
	// UpdatedAt is the newest non-removed version's created_at; zero when the
	// bundle has none.
	UpdatedAt time.Time
	// Downloads30d sums the bundle's non-removed versions over the 30 UTC
	// days ending today.
	Downloads30d int64
}

// statsQuery builds the one query behind ListStats. Arguments, in order:
// first day of the window, owner, owner, limit, offset.
//
// The CTE (INDEXED BY pins the plan: with no ANALYZE statistics SQLite would
// otherwise scan the primary key) aggregates the 30-day window by range scan of downloads_day (a
// covering index, so no table access) and joins versions only to drop removed
// ones; everything else is per-bundle indexed lookups. Every ORDER BY ends in
// (login, name), which is unique, so paging is deterministic.
func statsQuery(sort string) string {
	order := `u.login, b.name`
	switch sort {
	case SortRecent:
		order = `updated DESC, u.login, b.name` // NULL (no live version) sorts last
	case SortDownloads:
		order = `dl DESC, u.login, b.name`
	}
	return `WITH recent AS (
		SELECT d.owner_id AS owner_id, d.name AS name, SUM(d.count) AS c
		FROM downloads d INDEXED BY downloads_day JOIN versions v ON v.owner_id = d.owner_id AND v.name = d.name AND v.version = d.version
		WHERE d.day >= ? AND v.removed = 0 GROUP BY d.owner_id, d.name)
	SELECT u.id, u.login, u.kind, b.name,
		(SELECT max(v.created_at) FROM versions v WHERE v.owner_id = b.owner_id AND v.name = b.name AND v.removed = 0) AS updated,
		COALESCE(r.c, 0) AS dl
	FROM bundles b JOIN users u ON u.id = b.owner_id
		LEFT JOIN recent r ON r.owner_id = b.owner_id AND r.name = b.name
	WHERE u.login NOT LIKE '~%' AND NOT EXISTS (SELECT 1 FROM banned_users bu WHERE bu.user_id = u.id)
		AND (? = '' OR u.login = ? COLLATE NOCASE)
	ORDER BY ` + order + ` LIMIT ? OFFSET ?`
}

// ListStats is ListByOwner with each bundle's updatedAt and 30-day downloads,
// in the requested order (SortName is ListByOwner's order). Sorting happens
// over the whole filtered set before limit/offset apply; a negative limit
// means no limit. It loads no manifests.
func (s *Store) ListStats(owner, sort string, limit, offset int) ([]BundleStat, error) {
	rows, err := s.db.Query(statsQuery(sort), s.windowStart(), owner, owner, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BundleStat{}
	for rows.Next() {
		var (
			b       BundleStat
			updated sql.NullInt64
		)
		if err := rows.Scan(&b.Owner, &b.OwnerLogin, &b.OwnerKind, &b.Name, &updated, &b.Downloads30d); err != nil {
			return nil, err
		}
		if updated.Valid {
			b.UpdatedAt = time.Unix(updated.Int64, 0).UTC()
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// rollupDownloads folds daily rows older than retentionDays into one row per
// (owner, name, version) with day = dayBeforeWindow, in one transaction, so
// all-time totals are unchanged. Idempotent: a second run finds nothing to
// fold. Rows exactly retentionDays old are kept.
func (s *Store) rollupDownloads() error {
	cutoff := dayNumber(s.now()) - retentionDays
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`INSERT INTO downloads(owner_id, name, version, day, count)
		SELECT owner_id, name, version, ?, SUM(count) FROM downloads
		WHERE day > ? AND day < ? GROUP BY owner_id, name, version
		ON CONFLICT(owner_id, name, version, day) DO UPDATE SET count = count + excluded.count`,
		dayBeforeWindow, dayBeforeWindow, cutoff); err != nil {
		return err
	}
	res, err := tx.Exec(`DELETE FROM downloads WHERE day > ? AND day < ?`, dayBeforeWindow, cutoff)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		log.Printf("store: rolled %d daily download rows older than %d days into totals", n, retentionDays)
	}
	return nil
}
