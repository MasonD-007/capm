package store

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

// Account kinds (users.kind).
//
// ASSUMPTION: GitHub user ids and organisation ids share one id space (both
// are "accounts": GET /user/<id> answers for either, and an id is never
// reused for the other type), so a single table keyed by id can hold both
// without two accounts ever colliding. The store does not rely on that alone:
// an id's kind is fixed the first time it is recorded, and any attempt to
// record it as the other kind is refused (ErrKindChange) and logged, because
// it would be an account-type confusion (an organisation row suddenly
// treated as a person, or the reverse).
const (
	KindUser = "user"
	KindOrg  = "org"
)

// Membership roles recorded in org_members. RoleAdmin is an organisation
// owner (GitHub membership role "admin"). RoleMember is a plain member whose
// organisation's base repository permission was verified at login to be write
// or admin; a plain member without that is never recorded (see
// auth.qualifyingOrgs), so a row is the record that the user may publish.
const (
	RoleAdmin  = "admin"
	RoleMember = "member"
)

// OrgMembershipTTL is how long an org_members row authorises publishing,
// counted from checked_at. It bounds how long a removed member keeps access:
// the registry only learns about a removal at the next `capm login --orgs`.
const OrgMembershipTTL = 24 * time.Hour

// ErrKindChange is returned when an id already recorded as one kind is
// presented as the other.
var ErrKindChange = errors.New("store: an account id cannot change kind")

// Account is a row of users: a person or an organisation.
type Account struct {
	ID    int64
	Login string
	Kind  string
}

// upsertAccount records that GitHub account id currently has login and is of
// the given kind. GitHub logins can be reassigned: any other id holding this
// login is tombstoned as "~<id>" (which cannot match a URL owner) so logins
// stay unique. An existing id of a different kind is refused before anything
// is written.
func upsertAccount(x interface {
	execer
	QueryRow(query string, args ...any) *sql.Row
}, id int64, login, kind string) error {
	if kind != KindUser && kind != KindOrg {
		return fmt.Errorf("store: unknown account kind %q", kind)
	}
	var have string
	switch err := x.QueryRow(`SELECT kind FROM users WHERE id = ?`, id).Scan(&have); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return err
	case have != kind:
		log.Printf("store: refused to record account %d as %s: it is recorded as %s", id, kind, have)
		return ErrKindChange
	}
	if _, err := x.Exec(`UPDATE users SET login = '~' || id WHERE login = ? AND id != ?`, login, id); err != nil {
		return err
	}
	_, err := x.Exec(`INSERT INTO users(id, login, kind) VALUES(?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET login = excluded.login`, id, login, kind)
	return err
}

// upsertUser records a person (see upsertAccount).
func upsertUser(x interface {
	execer
	QueryRow(query string, args ...any) *sql.Row
}, id int64, login string) error {
	return upsertAccount(x, id, login, KindUser)
}

// UpsertUser records the current login of a GitHub user.
func (s *Store) UpsertUser(id int64, login string) error { return s.upsert(id, login, KindUser) }

// UpsertOrg records the current login of a GitHub organisation. Callers must
// have GitHub's own statement that id is an organisation (see auth).
func (s *Store) UpsertOrg(id int64, login string) error { return s.upsert(id, login, KindOrg) }

func (s *Store) upsert(id int64, login, kind string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := upsertAccount(tx, id, login, kind); err != nil {
		return err
	}
	return tx.Commit()
}

// AccountByLogin resolves a login (case-insensitive) to its account.
// Tombstoned ids are not addressable.
func (s *Store) AccountByLogin(login string) (Account, error) {
	var a Account
	if login == "" || strings.HasPrefix(login, "~") {
		return a, ErrNotFound
	}
	err := s.db.QueryRow(`SELECT id, login, kind FROM users WHERE login = ?`, login).Scan(&a.ID, &a.Login, &a.Kind)
	if errors.Is(err, sql.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	return a, err
}

// OrgRecord is one organisation a user may publish under, as established by
// GitHub at login.
type OrgRecord struct {
	OrgID int64
	Login string
	Role  string
}

// OrgMembership is a stored org_members row with the organisation's login.
type OrgMembership struct {
	OrgID     int64
	OrgLogin  string
	Role      string
	CheckedAt time.Time
	// Fresh is whether the record authorises publishing right now (see
	// FreshOrgRole).
	Fresh bool
}

// ReplaceOrgMemberships makes recs the complete set of organisations userID
// may publish under, as of now: every earlier record of the user is deleted
// (so leaving an organisation takes effect), each org is recorded in users
// with kind org (same login/tombstone handling as users) and each record gets
// checked_at = now, all in one transaction. A record naming an id that is
// recorded as a user is skipped and logged (never converted), a malformed
// record is an error and nothing changes.
func (s *Store) ReplaceOrgMemberships(userID int64, recs []OrgRecord) error {
	for _, r := range recs {
		if r.OrgID <= 0 || r.Login == "" || strings.HasPrefix(r.Login, "~") ||
			(r.Role != RoleAdmin && r.Role != RoleMember) {
			return fmt.Errorf("store: invalid organisation record for org %d", r.OrgID)
		}
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM org_members WHERE user_id = ?`, userID); err != nil {
		return err
	}
	now := s.now().Unix()
	for _, r := range recs {
		if err := upsertAccount(tx, r.OrgID, r.Login, KindOrg); err != nil {
			if errors.Is(err, ErrKindChange) {
				continue // logged by upsertAccount; no membership for it
			}
			return err
		}
		if _, err := tx.Exec(`INSERT INTO org_members(org_id, user_id, role, checked_at) VALUES(?,?,?,?)
			ON CONFLICT(org_id, user_id) DO UPDATE SET role = excluded.role, checked_at = excluded.checked_at`,
			r.OrgID, userID, r.Role, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// OrgMemberships lists userID's records (fresh or not), by org login.
func (s *Store) OrgMemberships(userID int64) ([]OrgMembership, error) {
	rows, err := s.db.Query(`SELECT m.org_id, u.login, m.role, m.checked_at FROM org_members m
		JOIN users u ON u.id = m.org_id AND u.kind = 'org'
		WHERE m.user_id = ? AND u.login NOT LIKE '~%' ORDER BY u.login`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OrgMembership{}
	for rows.Next() {
		var m OrgMembership
		var ts int64
		if err := rows.Scan(&m.OrgID, &m.OrgLogin, &m.Role, &ts); err != nil {
			return nil, err
		}
		m.CheckedAt = time.Unix(ts, 0).UTC()
		m.Fresh = s.freshRecord(m.Role, ts)
		out = append(out, m)
	}
	return out, rows.Err()
}

// FreshOrgRole returns userID's role in org orgID when a record exists, is
// not older than OrgMembershipTTL, is not dated in the future, and holds a
// role that may publish. Anything else (including a lookup error) is not ok.
func (s *Store) FreshOrgRole(orgID, userID int64) (role string, ok bool, err error) {
	var ts int64
	err = s.db.QueryRow(`SELECT m.role, m.checked_at FROM org_members m
		JOIN users u ON u.id = m.org_id AND u.kind = 'org'
		WHERE m.org_id = ? AND m.user_id = ?`, orgID, userID).Scan(&role, &ts)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !s.freshRecord(role, ts) {
		return "", false, nil
	}
	return role, true, nil
}

// freshRecord is the one definition of "this record still authorises": a
// known role, checked no more than OrgMembershipTTL ago and not in the future.
func (s *Store) freshRecord(role string, checkedAt int64) bool {
	age := s.now().Sub(time.Unix(checkedAt, 0))
	return age >= 0 && age <= OrgMembershipTTL && (role == RoleAdmin || role == RoleMember)
}

// HasStaleOrgRecord reports whether userID has a record for orgID at all
// (used only to tell the user to run `capm login --orgs` again).
func (s *Store) HasStaleOrgRecord(orgID, userID int64) (bool, error) {
	n, err := count(s.db, `SELECT count(*) FROM org_members WHERE org_id = ? AND user_id = ?`, orgID, userID)
	return n > 0, err
}
