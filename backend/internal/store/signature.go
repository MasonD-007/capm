package store

import (
	"database/sql"
	"errors"
)

// MaxSignatureBytes caps a stored signature bundle (64 KiB). The API enforces
// it on the request body and the store enforces it again, so no caller can put
// more in.
const MaxSignatureBytes = 64 << 10

var (
	// ErrSignatureExists: the version already has its one signature.
	ErrSignatureExists = errors.New("store: a signature already exists for this version")
	// ErrSignatureTooLarge: the bundle is over MaxSignatureBytes.
	ErrSignatureTooLarge = errors.New("store: signature bundle too large")
)

// A signature is a Sigstore bundle a CI workflow produced for a version's
// tarball. The registry only stores and serves the bytes; it never parses
// beyond the API's shape check, never verifies, and its word is never trusted:
// the CLI verifies the bundle against the tarball digest and the owner's
// identity.
//
// Storage accounting: signature bytes do NOT count toward storage quotas.
// A signature is write-once, at most MaxSignatureBytes, one per version, and
// can only exist for a version that exists, so the signatures table is
// bounded by the versions table (and a version is itself quota-bound).
//
// Lifecycle: yanking keeps the signature. Removing a version (takedown)
// deletes its row in the same transaction; restoring a version does not bring
// the signature back (the row is gone, so a new one may be uploaded).

// PutSignature stores bundle as the signature of ownerID's name@version. It is
// write-once: the primary key (owner_id, name, version) makes a second upload
// fail with ErrSignatureExists, inside the one transaction that checked the
// version exists, so two concurrent uploads yield exactly one success. A
// version that does not exist, or was removed, is ErrNotFound. uploadedBy is
// the acting user's id (nil when no human user acted).
//
// The store has one connection, so this transaction and RemoveVersion's are
// serialised; blobMu is not needed (no blob is touched).
func (s *Store) PutSignature(ownerID int64, name, version string, bundle []byte, uploadedBy *int64) error {
	if len(bundle) > MaxSignatureBytes {
		return ErrSignatureTooLarge
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var removed int
	err = tx.QueryRow(`SELECT removed FROM versions WHERE owner_id = ? AND name = ? AND version = ?`,
		ownerID, name, version).Scan(&removed)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && removed != 0) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO signatures(owner_id, name, version, bundle, created_at, uploaded_by)
		VALUES(?, ?, ?, ?, ?, ?)`, ownerID, name, version, bundle, s.now().Unix(), uploadedBy); err != nil {
		if isPK(err) || isUnique(err) {
			return ErrSignatureExists
		}
		return err
	}
	return tx.Commit()
}

// Signature returns the stored bytes exactly as uploaded. ErrNotFound when the
// version has no signature, does not exist, was removed, or its owner is
// banned.
func (s *Store) Signature(ownerLogin, name, version string) ([]byte, error) {
	var b []byte
	err := s.db.QueryRow(`SELECT sg.bundle FROM signatures sg
		JOIN versions v ON v.owner_id = sg.owner_id AND v.name = sg.name AND v.version = sg.version
		JOIN users u ON u.id = v.owner_id
		WHERE u.login = ? AND v.name = ? AND v.version = ? AND v.removed = 0`+notBanned,
		ownerLogin, name, version).Scan(&b)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return b, err
}

// signedExpr is a column expression (over versions aliased v) that is 1 when
// the version has a signature and is not removed. It is an indexed existence
// probe on the signatures primary key; no bundle bytes are read.
const signedExpr = `EXISTS (SELECT 1 FROM signatures sg WHERE sg.owner_id = v.owner_id AND sg.name = v.name AND sg.version = v.version AND v.removed = 0)`

// deleteSignatures drops the signature rows of one owner's versions of name;
// version "" means every version. Used by takedown and restore.
func deleteSignatures(tx *sql.Tx, owner int64, name, version string) error {
	_, err := tx.Exec(`DELETE FROM signatures WHERE owner_id = ? AND name = ? AND (? = '' OR version = ?)`,
		owner, name, version, version)
	return err
}
