package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func publish(t *testing.T, s *Store, id int64, login, name, version string) string {
	t.Helper()
	if err := s.Publish(id, login, name, version, bundle(t, name, version)); err != nil {
		t.Fatal(err)
	}
	vs, err := s.Versions(login, name)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		if v.Version == version {
			return v.Digest
		}
	}
	t.Fatal("published version missing")
	return ""
}

func blobPath(s *Store, digest string) string {
	return filepath.Join(s.blobsDir, strings.TrimPrefix(digest, "sha256:"))
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func TestRemovedVersionBlobErrRemoved(t *testing.T) {
	s := openStore(t)
	d := publish(t, s, 1, "alice", "x", "1.0.0")
	if _, err := s.RemoveVersion(99, "alice", "x", "1.0.0", "malware"); err != nil {
		t.Fatal(err)
	}
	_, err := s.Blob("alice", "x", "1.0.0")
	if !errors.Is(err, ErrRemoved) {
		t.Fatalf("err = %v, want ErrRemoved", err)
	}
	var re *RemovedError
	if !errors.As(err, &re) || re.Reason != "malware" {
		t.Fatalf("reason: %v", err)
	}
	if exists(blobPath(s, d)) {
		t.Fatal("blob should be deleted")
	}
	vs, err := s.Versions("alice", "x")
	if err != nil || len(vs) != 1 || !vs[0].Removed || vs[0].RemovedReason != "malware" {
		t.Fatalf("%+v %v", vs, err)
	}
	// The version number can never be republished.
	if err := s.Publish(1, "alice", "x", "1.0.0", bundle(t, "x", "1.0.0")); !errors.Is(err, ErrVersionExists) {
		t.Fatalf("republish: %v", err)
	}
}

func TestRemoveKeepsSharedBlob(t *testing.T) {
	s := openStore(t)
	d1 := publish(t, s, 1, "alice", "x", "1.0.0")
	d2 := publish(t, s, 2, "bob", "x", "1.0.0") // identical tarball, other owner
	if d1 != d2 {
		t.Skipf("tarballs are not byte-identical (%s vs %s)", d1, d2)
	}
	res, err := s.RemoveVersion(99, "alice", "x", "1.0.0", "r")
	if err != nil {
		t.Fatal(err)
	}
	if res.BlobsDeleted != 0 || !exists(blobPath(s, d1)) {
		t.Fatalf("shared blob must stay: %+v", res)
	}
	if _, err := s.Blob("bob", "x", "1.0.0"); err != nil {
		t.Fatalf("bob's download broke: %v", err)
	}
	res, err = s.RemoveVersion(99, "bob", "x", "1.0.0", "r")
	if err != nil {
		t.Fatal(err)
	}
	if res.BlobsDeleted != 1 || exists(blobPath(s, d1)) {
		t.Fatalf("last reference removed: blob must go: %+v", res)
	}
}

func TestRemoveKeepsBlobSharedWithinBundle(t *testing.T) {
	s := openStore(t)
	d := publish(t, s, 1, "alice", "x", "1.0.0")
	// Another row pointing at the same digest, as a second owner would create.
	if _, err := s.db.Exec(`INSERT INTO users(id, login) VALUES (2,'bob')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO versions(owner_id,name,version,digest,manifest,created_at) VALUES (2,'y','1.0.0',?, '{}', 1)`, d); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoveVersion(99, "alice", "x", "1.0.0", "r"); err != nil {
		t.Fatal(err)
	}
	if !exists(blobPath(s, d)) {
		t.Fatal("blob still referenced by a live row was deleted")
	}
}

func TestRemoveBlobDeleteFailureNotFatal(t *testing.T) {
	s := openStore(t)
	d := publish(t, s, 1, "alice", "x", "1.0.0")
	p := blobPath(s, d)
	// Make os.Remove fail: replace the file by a non-empty directory.
	os.Remove(p)
	os.MkdirAll(filepath.Join(p, "sub"), 0o755)
	res, err := s.RemoveVersion(99, "alice", "x", "1.0.0", "r")
	if err != nil {
		t.Fatalf("a failed file delete must not fail the removal: %v", err)
	}
	if res.BlobsDeleted != 0 {
		t.Fatalf("%+v", res)
	}
	vs, _ := s.Versions("alice", "x")
	if !vs[0].Removed {
		t.Fatal("row must still be marked removed")
	}
}

func TestRemoveStates(t *testing.T) {
	s := openStore(t)
	publish(t, s, 1, "alice", "x", "1.0.0")
	if _, err := s.RemoveVersion(99, "alice", "x", "9.9.9", "r"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
	if _, err := s.RemoveVersion(99, "nobody", "x", "1.0.0", "r"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
	if _, err := s.RemoveVersion(99, "alice", "x", "1.0.0", "r"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoveVersion(99, "alice", "x", "1.0.0", "r"); !errors.Is(err, ErrAlreadyRemoved) {
		t.Fatalf("%v", err)
	}
	var n int
	s.db.QueryRow(`SELECT count(*) FROM admin_actions`).Scan(&n)
	if n != 1 {
		t.Fatalf("failed/no-op removals must not write audit rows, got %d", n)
	}
}

func TestRemoveBundleAndAudit(t *testing.T) {
	s := openStore(t)
	publish(t, s, 1, "alice", "x", "1.0.0")
	publish(t, s, 1, "alice", "x", "1.1.0")
	publish(t, s, 1, "alice", "other", "1.0.0")
	if _, err := s.RemoveVersion(99, "alice", "x", "1.0.0", "first"); err != nil {
		t.Fatal(err)
	}
	res, err := s.RemoveBundle(99, "alice", "x", "whole bundle")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Versions) != 1 || res.Versions[0] != "1.1.0" {
		t.Fatalf("%+v", res)
	}
	vs, _ := s.Versions("alice", "x")
	if vs[0].RemovedReason != "first" || vs[1].RemovedReason != "whole bundle" {
		t.Fatalf("reasons: %+v", vs)
	}
	if o, _ := s.Versions("alice", "other"); o[0].Removed {
		t.Fatal("other bundle touched")
	}
	if _, err := s.RemoveBundle(99, "alice", "x", "again"); !errors.Is(err, ErrAlreadyRemoved) {
		t.Fatalf("%v", err)
	}
	if _, err := s.RemoveBundle(99, "alice", "nope", "r"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
	log, err := s.AdminLog(10)
	if err != nil || len(log) != 2 {
		t.Fatalf("%+v %v", log, err)
	}
	if log[0].Action != "remove_bundle" || log[0].Target != "alice/x" || log[0].Reason != "whole bundle" || log[0].AdminID != 99 {
		t.Fatalf("newest first: %+v", log[0])
	}
	if log[1].Action != "remove_version" || log[1].Target != "alice/x@1.0.0" {
		t.Fatalf("%+v", log[1])
	}
}

func TestAuditRolledBackWithChange(t *testing.T) {
	s := openStore(t)
	publish(t, s, 1, "alice", "x", "1.0.0")
	// Break the audit table so the audit insert fails: the change must roll back.
	if _, err := s.db.Exec(`DROP TABLE admin_actions`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoveVersion(99, "alice", "x", "1.0.0", "r"); err == nil {
		t.Fatal("expected error")
	}
	vs, _ := s.Versions("alice", "x")
	if vs[0].Removed {
		t.Fatal("removal committed without its audit row")
	}
	if !exists(blobPath(s, vs[0].Digest)) {
		t.Fatal("blob deleted despite rollback")
	}
}

func TestRestore(t *testing.T) {
	s := openStore(t)
	d := publish(t, s, 1, "alice", "x", "1.0.0")
	if err := s.RestoreVersion(99, "alice", "x", "1.0.0"); !errors.Is(err, ErrNotRemoved) {
		t.Fatalf("%v", err)
	}
	if _, err := s.RemoveVersion(99, "alice", "x", "1.0.0", "r"); err != nil {
		t.Fatal(err)
	}
	// Blob was deleted: cannot restore, and nothing changes.
	if err := s.RestoreVersion(99, "alice", "x", "1.0.0"); !errors.Is(err, ErrBlobMissing) {
		t.Fatalf("%v", err)
	}
	vs, _ := s.Versions("alice", "x")
	if !vs[0].Removed {
		t.Fatal("must stay removed")
	}
	// Put the blob back (e.g. restored from backup): now it can be restored.
	if err := os.WriteFile(blobPath(s, d), bundle(t, "x", "1.0.0"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.RestoreVersion(99, "alice", "x", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	vs, _ = s.Versions("alice", "x")
	if vs[0].Removed || vs[0].RemovedReason != "" {
		t.Fatalf("%+v", vs[0])
	}
	if _, err := s.Blob("alice", "x", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	log, _ := s.AdminLog(10)
	if log[0].Action != "restore_version" || log[0].Target != "alice/x@1.0.0" {
		t.Fatalf("%+v", log[0])
	}
}

func TestRestoreBundlePartial(t *testing.T) {
	s := openStore(t)
	d1 := publish(t, s, 1, "alice", "x", "1.0.0")
	publish(t, s, 1, "alice", "x", "1.1.0")
	if _, err := s.RemoveBundle(99, "alice", "x", "r"); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(blobPath(s, d1), bundle(t, "x", "1.0.0"), 0o644)
	res, err := s.RestoreBundle(99, "alice", "x")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Restored) != 1 || res.Restored[0] != "1.0.0" || len(res.Skipped) != 1 || res.Skipped[0] != "1.1.0" {
		t.Fatalf("%+v", res)
	}
	// Nothing restorable left: conflict.
	if _, err := s.RestoreBundle(99, "alice", "x"); !errors.Is(err, ErrBlobMissing) {
		t.Fatalf("%v", err)
	}
	if _, err := s.RestoreBundle(99, "alice", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
}

func TestBanHidesBundles(t *testing.T) {
	s := openStore(t)
	publish(t, s, 1, "alice", "x", "1.0.0")
	publish(t, s, 2, "bob", "y", "1.0.0")
	if b, _ := s.IsBanned(1); b {
		t.Fatal("not banned yet")
	}
	if err := s.BanUser(99, 1, "spam"); err != nil {
		t.Fatal(err)
	}
	if err := s.BanUser(99, 1, "spam"); !errors.Is(err, ErrAlreadyBanned) {
		t.Fatalf("%v", err)
	}
	if b, _ := s.IsBanned(1); !b {
		t.Fatal("banned")
	}
	bs, err := s.List(50, 0)
	if err != nil || len(bs) != 1 || bs[0].OwnerLogin != "bob" {
		t.Fatalf("%+v %v", bs, err)
	}
	if bs, _ := s.ListByOwner("alice", 50, 0); len(bs) != 0 {
		t.Fatalf("owner filter leaks banned user: %+v", bs)
	}
	if _, err := s.Versions("alice", "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Versions: %v", err)
	}
	if _, err := s.Blob("alice", "x", "1.0.0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Blob: %v", err)
	}
	if err := s.UnbanUser(99, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.UnbanUser(99, 1); !errors.Is(err, ErrNotBanned) {
		t.Fatalf("%v", err)
	}
	if bs, _ := s.List(50, 0); len(bs) != 2 {
		t.Fatalf("unban must restore visibility: %+v", bs)
	}
	log, _ := s.AdminLog(10)
	if len(log) != 2 || log[0].Action != "unban_user" || log[1].Action != "ban_user" || log[1].Target != "user:1" || log[1].Reason != "spam" {
		t.Fatalf("%+v", log)
	}
}

func TestUserIDByLogin(t *testing.T) {
	s := openStore(t)
	publish(t, s, 7, "Alice", "x", "1.0.0")
	if id, err := s.UserIDByLogin("alice"); err != nil || id != 7 {
		t.Fatalf("%d %v", id, err)
	}
	if _, err := s.UserIDByLogin("zed"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("%v", err)
	}
}
