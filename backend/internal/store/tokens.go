package store

import (
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"
)

// touchInterval is how stale last_used_at may get before a request writes it.
const touchInterval = time.Hour

// purgeAfter is how long expired or revoked token rows are kept.
const purgeAfter = 30 * 24 * time.Hour

// Token is a resolved, currently valid token.
type Token struct {
	ID         int64
	UserID     int64
	Login      string
	ExpiresAt  time.Time // zero = never expires
	LastUsedAt time.Time // zero = never used
	hash       []byte
}

// TokenInfo describes one of a user's tokens. It deliberately carries no hash.
type TokenInfo struct {
	ID         int64
	Name       string
	CreatedAt  time.Time
	LastUsedAt time.Time // zero = never used
	ExpiresAt  time.Time // zero = never expires
	Current    bool
}

func unixOrZero(n sql.NullInt64) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return time.Unix(n.Int64, 0).UTC()
}

// CreateToken stores the hash of an API token for userID. The raw token is
// never stored. A zero expiresAt means the token never expires. The public id
// is allocated inside the INSERT itself: SQLite runs the whole statement under
// the single write lock (and Open limits the pool to one connection), so two
// concurrent calls cannot read the same MAX(id); the UNIQUE index is a
// backstop.
func (s *Store) CreateToken(hash []byte, userID int64, name string, expiresAt time.Time) error {
	var exp any
	if !expiresAt.IsZero() {
		exp = expiresAt.Unix()
	}
	_, err := s.db.Exec(`INSERT INTO tokens(hash, user_id, created_at, name, expires_at, id)
		VALUES(?, ?, ?, ?, ?, (SELECT COALESCE(MAX(id), 0) + 1 FROM tokens))`,
		hash, userID, s.now().Unix(), name, exp)
	return err
}

// LookupToken resolves a token hash to its user. Unknown, expired and revoked
// tokens all give ErrNotFound.
func (s *Store) LookupToken(hash []byte) (Token, error) {
	var (
		tk      Token
		stored  []byte
		exp, lu sql.NullInt64
	)
	err := s.db.QueryRow(`SELECT u.id, u.login, t.hash, t.id, t.expires_at, t.last_used_at
		FROM tokens t JOIN users u ON u.id = t.user_id
		WHERE t.hash = ? AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > ?)`,
		hash, s.now().Unix()).Scan(&tk.UserID, &tk.Login, &stored, &tk.ID, &exp, &lu)
	if errors.Is(err, sql.ErrNoRows) {
		return Token{}, ErrNotFound
	}
	if err != nil {
		return Token{}, err
	}
	if subtle.ConstantTimeCompare(stored, hash) != 1 {
		return Token{}, ErrNotFound
	}
	tk.ExpiresAt, tk.LastUsedAt, tk.hash = unixOrZero(exp), unixOrZero(lu), stored
	return tk, nil
}

// UserByTokenHash resolves a token hash to the user's id and current login.
func (s *Store) UserByTokenHash(hash []byte) (int64, string, error) {
	tk, err := s.LookupToken(hash)
	if err != nil {
		return 0, "", err
	}
	return tk.UserID, tk.Login, nil
}

// TouchToken records a use of tk, at most once per touchInterval. It never
// fails the caller: the write happens only when the stored value is stale
// (so ordinary reads take no write lock) and errors are only logged.
func (s *Store) TouchToken(tk Token) {
	now := s.now()
	if !tk.LastUsedAt.IsZero() && now.Sub(tk.LastUsedAt) < touchInterval {
		return
	}
	if _, err := s.db.Exec(`UPDATE tokens SET last_used_at = ?
		WHERE hash = ? AND (last_used_at IS NULL OR last_used_at < ?)`,
		now.Unix(), tk.hash, now.Add(-touchInterval).Unix()); err != nil {
		log.Printf("store: touch token: %v", err)
	}
}

// ListTokens returns userID's usable (not revoked, not expired) tokens,
// oldest first. currentHash marks the caller's own token.
func (s *Store) ListTokens(userID int64, currentHash []byte) ([]TokenInfo, error) {
	rows, err := s.db.Query(`SELECT id, name, created_at, last_used_at, expires_at, hash
		FROM tokens WHERE user_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)
		ORDER BY id`, userID, s.now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TokenInfo{}
	for rows.Next() {
		var (
			ti      TokenInfo
			created int64
			lu, exp sql.NullInt64
			h       []byte
		)
		if err := rows.Scan(&ti.ID, &ti.Name, &created, &lu, &exp, &h); err != nil {
			return nil, err
		}
		ti.CreatedAt = time.Unix(created, 0).UTC()
		ti.LastUsedAt, ti.ExpiresAt = unixOrZero(lu), unixOrZero(exp)
		ti.Current = currentHash != nil && subtle.ConstantTimeCompare(h, currentHash) == 1
		out = append(out, ti)
	}
	return out, rows.Err()
}

// RevokeToken revokes userID's token with the given public id. A token that
// does not exist, belongs to someone else or is already revoked is ErrNotFound.
func (s *Store) RevokeToken(userID, id int64) error {
	res, err := s.db.Exec(`UPDATE tokens SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL`,
		s.now().Unix(), id, userID)
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

// RevokeAllTokens revokes every live token of userID on behalf of adminID and
// writes the audit row in the same transaction. It returns how many were
// revoked.
func (s *Store) RevokeAllTokens(adminID, userID int64) (int, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`,
		s.now().Unix(), userID)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if err := audit(tx, adminID, "revoke_tokens", fmt.Sprintf("user:%d", userID), ""); err != nil {
		return 0, err
	}
	return int(n), tx.Commit()
}

// PurgeTokens deletes rows that expired or were revoked more than 30 days ago.
// The row holding the highest id is always kept so that new ids (MAX+1) are
// never ones that were handed out before.
func (s *Store) PurgeTokens() (int64, error) {
	cutoff := s.now().Add(-purgeAfter).Unix()
	res, err := s.db.Exec(`DELETE FROM tokens
		WHERE ((expires_at IS NOT NULL AND expires_at < ?) OR (revoked_at IS NOT NULL AND revoked_at < ?))
		AND id < (SELECT MAX(id) FROM tokens)`, cutoff, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
