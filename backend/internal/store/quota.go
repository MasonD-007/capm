package store

import (
	"database/sql"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// backfillSizes fills versions.size for rows where it is NULL by statting the
// blob file. It runs on every Open after the migrations: after migration 4,
// and again after a rollback to a release that inserts versions without a
// size. A blob that is not on disk (a removed version, or damage) gets size
// 0; those are counted and logged once, because the NULL is gone afterwards.
// Idempotent: it only touches NULL rows, so with none it is one cheap query.
func backfillSizes(db *sql.DB, blobsDir string) error {
	rows, err := db.Query(`SELECT DISTINCT digest FROM versions WHERE size IS NULL`)
	if err != nil {
		return err
	}
	var digests []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err != nil {
			rows.Close()
			return err
		}
		digests = append(digests, d)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(digests) == 0 {
		return nil
	}
	missing := 0
	for _, d := range digests {
		var size int64
		fi, err := os.Stat(filepath.Join(blobsDir, strings.TrimPrefix(d, "sha256:")))
		switch {
		case err == nil:
			size = fi.Size()
		case errors.Is(err, os.ErrNotExist):
			missing++
		default:
			return err // unreadable: leave NULL, try again next start
		}
		if _, err := db.Exec(`UPDATE versions SET size = ? WHERE digest = ? AND size IS NULL`, size, d); err != nil {
			return err
		}
	}
	log.Printf("store: recorded blob sizes for %d digests (%d had no blob on disk and count as 0 bytes)", len(digests), missing)
	return nil
}
