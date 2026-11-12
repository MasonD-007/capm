package store

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"
)

// Storage accounting. This comment is the single definition; the queries
// below implement it and the tests pin each rule.
//
//   - A user's bytes are the sum of size over the DISTINCT digests among that
//     owner's versions that are not removed. Yanked versions count (their blob
//     is still stored). A removed version does not: a takedown deletes the
//     blob unless another live version still references the digest, and in
//     that case it is the other holder's storage, not this owner's.
//   - A user's bundle count is the number of that owner's bundle names with at
//     least one versions row, removed and yanked rows included.
//   - A bundle's version count is its number of rows, removed and yanked
//     included (version numbers are never reused).
//   - Registry-wide bytes are the sum of size over the distinct digests among
//     all versions that are not removed.
//   - Publishing bytes the owner already stores adds 0 to their bytes (it is
//     still a version); bytes some other owner already stores add 0 to the
//     registry total but are charged in full to this owner.
//   - A NULL size (a row a rolled-back release inserted, until the next Open
//     repairs it) counts as 0.
//   - A limit of 0 means unlimited. A byte limit only rejects a publish that
//     adds bytes, so a user already over a lowered limit can still add a
//     version that stores nothing new.

// Names of the limits, as they appear in API bodies.
const (
	LimitUserBytes      = "user_bytes"
	LimitUserBundles    = "user_bundles"
	LimitBundleVersions = "bundle_versions"
	LimitTotalBytes     = "total_bytes"
)

// Limits are the default limits; 0 disables a limit.
type Limits struct {
	UserBytes      int64 // stored bytes per owner
	UserBundles    int64 // bundle names per owner
	BundleVersions int64 // versions per bundle
	TotalBytes     int64 // stored bytes registry-wide
}

// DefaultLimits are used unless SetLimits says otherwise.
func DefaultLimits() Limits {
	return Limits{UserBytes: 100 << 20, UserBundles: 50, BundleVersions: 200, TotalBytes: 3 << 30}
}

// SetLimits replaces the default limits. Call it at startup, before the store
// serves requests.
func (s *Store) SetLimits(l Limits) { s.limits = l }

// ErrQuota is matched (errors.Is) by every *QuotaError.
var ErrQuota = errors.New("store: quota exceeded")

// QuotaError is a publish rejected by a limit. Limit is one of the Limit*
// constants. Error() is a sentence safe to show the publisher; for
// LimitTotalBytes it deliberately holds no registry-wide numbers (Used and Max
// are still set, for logs).
type QuotaError struct {
	Limit     string
	Used, Max int64
}

func (e *QuotaError) Is(target error) bool { return target == ErrQuota }

func (e *QuotaError) Error() string {
	switch e.Limit {
	case LimitUserBytes:
		return fmt.Sprintf("storage limit reached: you store %s of your %s limit and this bundle would exceed it. "+
			"Remove versions you no longer need, or ask the registry operator for a higher limit",
			HumanBytes(e.Used), HumanBytes(e.Max))
	case LimitUserBundles:
		return fmt.Sprintf("bundle limit reached: you already have %d bundles (limit %d). "+
			"Publish new versions of an existing bundle, or ask the registry operator for a higher limit", e.Used, e.Max)
	case LimitBundleVersions:
		return fmt.Sprintf("version limit reached: this bundle already has %d versions (limit %d)", e.Used, e.Max)
	case LimitTotalBytes:
		return "the registry is full and is not accepting new uploads right now; the operator has been alerted. Try again later"
	}
	return "quota exceeded"
}

// HumanBytes formats n in binary units, e.g. "100.0 MiB".
func HumanBytes(n int64) string {
	if n < 1024 {
		return fmt.Sprintf("%d B", n)
	}
	f := float64(n)
	for _, u := range []string{"KiB", "MiB", "GiB", "TiB"} {
		f /= 1024
		if f < 1024 || u == "TiB" {
			return fmt.Sprintf("%.1f %s", f, u)
		}
	}
	return ""
}

type queryer interface {
	QueryRow(query string, args ...any) *sql.Row
}

func count(q queryer, query string, args ...any) (int64, error) {
	var n int64
	err := q.QueryRow(query, args...).Scan(&n)
	return n, err
}

// One size per digest (MAX picks it; every row of a digest has the same size).
const sumDistinct = `SELECT COALESCE(SUM(sz), 0) FROM (SELECT MAX(COALESCE(size, 0)) AS sz FROM versions WHERE removed = 0`

func ownerBytes(q queryer, owner int64) (int64, error) {
	return count(q, sumDistinct+` AND owner_id = ? GROUP BY digest)`, owner)
}

func totalBytes(q queryer) (int64, error) {
	return count(q, sumDistinct+` GROUP BY digest)`)
}

func ownerBundles(q queryer, owner int64) (int64, error) {
	return count(q, `SELECT count(DISTINCT name) FROM versions WHERE owner_id = ?`, owner)
}

// override is a user's quota_overrides row; nil fields use the default.
type override struct{ bytes, bundles *int64 }

func getOverride(q queryer, owner int64) (override, error) {
	var b, n sql.NullInt64
	err := q.QueryRow(`SELECT max_bytes, max_bundles FROM quota_overrides WHERE user_id = ?`, owner).Scan(&b, &n)
	if errors.Is(err, sql.ErrNoRows) {
		return override{}, nil
	}
	var o override
	if b.Valid {
		o.bytes = &b.Int64
	}
	if n.Valid {
		o.bundles = &n.Int64
	}
	return o, err
}

// checkQuota decides whether owner may add a version of bundle name whose
// tarball has the given digest and size. It must run inside Publish's
// transaction, before the insert.
func (s *Store) checkQuota(tx *sql.Tx, owner int64, name, digest string, size int64) error {
	ov, err := getOverride(tx, owner)
	if err != nil {
		return err
	}
	maxBytes, maxBundles := s.limits.UserBytes, s.limits.UserBundles
	if ov.bytes != nil {
		maxBytes = *ov.bytes
	}
	if ov.bundles != nil {
		maxBundles = *ov.bundles
	}

	versions, err := count(tx, `SELECT count(*) FROM versions WHERE owner_id = ? AND name = ?`, owner, name)
	if err != nil {
		return err
	}
	if m := s.limits.BundleVersions; m > 0 && versions+1 > m {
		return &QuotaError{Limit: LimitBundleVersions, Used: versions, Max: m}
	}
	if versions == 0 && maxBundles > 0 { // a new bundle name
		n, err := ownerBundles(tx, owner)
		if err != nil {
			return err
		}
		if n+1 > maxBundles {
			return &QuotaError{Limit: LimitUserBundles, Used: n, Max: maxBundles}
		}
	}
	ownHas, err := count(tx, `SELECT count(*) FROM versions WHERE owner_id = ? AND digest = ? AND removed = 0`, owner, digest)
	if err != nil {
		return err
	}
	if ownHas == 0 && maxBytes > 0 {
		used, err := ownerBytes(tx, owner)
		if err != nil {
			return err
		}
		if used+size > maxBytes {
			return &QuotaError{Limit: LimitUserBytes, Used: used, Max: maxBytes}
		}
	}
	if m := s.limits.TotalBytes; m > 0 {
		anyHas, err := count(tx, `SELECT count(*) FROM versions WHERE digest = ? AND removed = 0`, digest)
		if err != nil {
			return err
		}
		if anyHas == 0 {
			total, err := totalBytes(tx)
			if err != nil {
				return err
			}
			if total+size > m {
				log.Printf("WARN: quota: registry storage limit total_bytes reached (%d of %d bytes stored); rejecting a %d byte publish by user %d. Free space or raise MAX_TOTAL_BYTES",
					total, m, size, owner)
				return &QuotaError{Limit: LimitTotalBytes, Used: total, Max: m}
			}
		}
	}
	return nil
}

// Usage is a user's current storage and the limits that apply to them. A Max
// of 0 means unlimited.
type Usage struct {
	Bytes             int64
	Bundles           int64
	MaxBytes          int64
	MaxBundles        int64
	MaxBundleVersions int64
	// BytesOverridden and BundlesOverridden say the limit comes from a
	// per-user override rather than the default.
	BytesOverridden   bool
	BundlesOverridden bool
}

// Usage reports userID's usage and effective limits. Unknown users have none.
func (s *Store) Usage(userID int64) (Usage, error) {
	u := Usage{MaxBytes: s.limits.UserBytes, MaxBundles: s.limits.UserBundles, MaxBundleVersions: s.limits.BundleVersions}
	var err error
	if u.Bytes, err = ownerBytes(s.db, userID); err != nil {
		return u, err
	}
	if u.Bundles, err = ownerBundles(s.db, userID); err != nil {
		return u, err
	}
	ov, err := getOverride(s.db, userID)
	if err != nil {
		return u, err
	}
	if ov.bytes != nil {
		u.MaxBytes, u.BytesOverridden = *ov.bytes, true
	}
	if ov.bundles != nil {
		u.MaxBundles, u.BundlesOverridden = *ov.bundles, true
	}
	return u, nil
}

// TotalBytes is the registry-wide stored bytes (see the accounting rules).
func (s *Store) TotalBytes() (int64, error) { return totalBytes(s.db) }

// SetQuotaOverride sets userID's own limits: a nil argument clears that
// override (the default applies); both nil removes the row. 0 means unlimited
// for that user. The change and its audit row commit together.
func (s *Store) SetQuotaOverride(adminID, userID int64, maxBytes, maxBundles *int64) error {
	for _, p := range []*int64{maxBytes, maxBundles} {
		if p != nil && *p < 0 {
			return errors.New("store: quota override must not be negative")
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if maxBytes == nil && maxBundles == nil {
		_, err = tx.Exec(`DELETE FROM quota_overrides WHERE user_id = ?`, userID)
	} else {
		_, err = tx.Exec(`INSERT INTO quota_overrides(user_id, max_bytes, max_bundles, updated_at) VALUES(?,?,?,?)
			ON CONFLICT(user_id) DO UPDATE SET max_bytes = excluded.max_bytes,
				max_bundles = excluded.max_bundles, updated_at = excluded.updated_at`,
			userID, maxBytes, maxBundles, time.Now().Unix())
	}
	if err != nil {
		return err
	}
	show := func(p *int64) string {
		if p == nil {
			return "default"
		}
		return fmt.Sprint(*p)
	}
	if err := audit(tx, adminID, "set_quota", fmt.Sprintf("user:%d", userID),
		"maxBytes="+show(maxBytes)+" maxBundles="+show(maxBundles)); err != nil {
		return err
	}
	return tx.Commit()
}
