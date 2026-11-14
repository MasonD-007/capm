package store

import (
	"bytes"
	"errors"
	"os"
	"strconv"
	"sync"
	"testing"
)

func publishX(t *testing.T, s *Store, versions ...string) {
	t.Helper()
	for _, v := range versions {
		if err := s.Publish(1, "alice", "x", v, bundle(t, "x", v)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSignatureRoundTripIsByteIdentical(t *testing.T) {
	s, _ := open(t)
	publishX(t, s, "1.0.0", "1.1.0")
	raw := []byte("  {\"verificationMaterial\" :{},\n\t\"mediaType\":\"a\",\"messageSignature\":{} }\r\n")
	by := int64(7)
	if err := s.PutSignature(1, "x", "1.0.0", raw, &by); err != nil {
		t.Fatal(err)
	}
	got, err := s.Signature("alice", "x", "1.0.0")
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := s.Signature("alice", "x", "1.1.0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unsigned version: %v", err)
	}
	vs, _ := s.Versions("alice", "x")
	if !vs[0].Signed || vs[1].Signed {
		t.Fatalf("signed flags: %+v", vs)
	}
	var ub *int64
	s.db.QueryRow(`SELECT uploaded_by FROM signatures`).Scan(&ub)
	if ub == nil || *ub != 7 {
		t.Fatalf("uploaded_by = %v", ub)
	}
}

func TestSignatureIsWriteOnce(t *testing.T) {
	s, _ := open(t)
	publishX(t, s, "1.0.0")
	if err := s.PutSignature(1, "x", "1.0.0", []byte(`{"a":1}`), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSignature(1, "x", "1.0.0", []byte(`{"a":2}`), nil); !errors.Is(err, ErrSignatureExists) {
		t.Fatalf("second put: %v", err)
	}
	if got, _ := s.Signature("alice", "x", "1.0.0"); string(got) != `{"a":1}` {
		t.Fatalf("first signature was replaced: %s", got)
	}
}

func TestConcurrentSignaturePutsExactlyOneWins(t *testing.T) {
	s, _ := open(t)
	publishX(t, s, "1.0.0")
	const n = 16
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = s.PutSignature(1, "x", "1.0.0", []byte(`{"n":`+strconv.Itoa(i)+`}`), nil)
		}()
	}
	wg.Wait()
	ok, exists := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, ErrSignatureExists):
			exists++
		default:
			t.Fatal(err)
		}
	}
	if ok != 1 || exists != n-1 {
		t.Fatalf("%d succeeded, %d conflicted", ok, exists)
	}
}

func TestSignatureNeedsAnExistingLiveVersion(t *testing.T) {
	s, _ := open(t)
	publishX(t, s, "1.0.0")
	if err := s.PutSignature(1, "x", "9.9.9", []byte(`{}`), nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown version: %v", err)
	}
	if err := s.PutSignature(1, "nope", "1.0.0", []byte(`{}`), nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown bundle: %v", err)
	}
	if err := s.PutSignature(2, "x", "1.0.0", []byte(`{}`), nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other owner: %v", err)
	}
	if _, err := s.RemoveVersion(99, "alice", "x", "1.0.0", "bad"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSignature(1, "x", "1.0.0", []byte(`{}`), nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed version: %v", err)
	}
	var n int
	s.db.QueryRow(`SELECT count(*) FROM signatures`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d rows for versions that cannot be signed", n)
	}
}

func TestSignatureSizeCapInStore(t *testing.T) {
	s, _ := open(t)
	publishX(t, s, "1.0.0")
	if err := s.PutSignature(1, "x", "1.0.0", bytes.Repeat([]byte("a"), MaxSignatureBytes+1), nil); !errors.Is(err, ErrSignatureTooLarge) {
		t.Fatalf("over cap: %v", err)
	}
	if err := s.PutSignature(1, "x", "1.0.0", bytes.Repeat([]byte("a"), MaxSignatureBytes), nil); err != nil {
		t.Fatalf("at cap: %v", err)
	}
}

func TestRemoveDeletesSignatureRestoreDoesNotBringItBack(t *testing.T) {
	s, _ := open(t)
	publishX(t, s, "1.0.0", "1.1.0")
	for _, v := range []string{"1.0.0", "1.1.0"} {
		if err := s.PutSignature(1, "x", v, []byte(`{"v":"`+v+`"}`), nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.RemoveVersion(99, "alice", "x", "1.0.0", "bad"); err != nil {
		t.Fatal(err)
	}
	var n int
	s.db.QueryRow(`SELECT count(*) FROM signatures WHERE version = '1.0.0'`).Scan(&n)
	if n != 0 {
		t.Fatal("the removed version's signature row survived")
	}
	s.db.QueryRow(`SELECT count(*) FROM signatures WHERE version = '1.1.0'`).Scan(&n)
	if n != 1 {
		t.Fatal("removing one version deleted another's signature")
	}
	if _, err := s.Signature("alice", "x", "1.0.0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed: %v", err)
	}
	// The takedown deleted the blob; put it back (as a backup restore would).
	vs, _ := s.Versions("alice", "x")
	if err := os.WriteFile(blobPath(s, vs[0].Digest), bundle(t, "x", "1.0.0"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.RestoreVersion(99, "alice", "x", "1.0.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Signature("alice", "x", "1.0.0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("restore brought the signature back: %v", err)
	}
	// The slot is free again.
	if err := s.PutSignature(1, "x", "1.0.0", []byte(`{"again":1}`), nil); err != nil {
		t.Fatal(err)
	}
	// Whole-bundle removal clears every signature.
	if _, err := s.RemoveBundle(99, "alice", "x", "bad"); err != nil {
		t.Fatal(err)
	}
	s.db.QueryRow(`SELECT count(*) FROM signatures`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d signature rows after removing the bundle", n)
	}
}

func TestYankKeepsSignature(t *testing.T) {
	s, _ := open(t)
	publishX(t, s, "1.0.0")
	if err := s.PutSignature(1, "x", "1.0.0", []byte(`{}`), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SetYanked(1, "x", "1.0.0", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Signature("alice", "x", "1.0.0"); err != nil {
		t.Fatalf("yanked version lost its signature: %v", err)
	}
	vs, _ := s.Versions("alice", "x")
	if !vs[0].Signed {
		t.Fatal("yanked version reports unsigned")
	}
}

func TestBannedOwnerServesNoSignature(t *testing.T) {
	s, _ := open(t)
	publishX(t, s, "1.0.0")
	if err := s.PutSignature(1, "x", "1.0.0", []byte(`{}`), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.BanUser(99, 1, "spam"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Signature("alice", "x", "1.0.0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("banned: %v", err)
	}
	if err := s.UnbanUser(99, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Signature("alice", "x", "1.0.0"); err != nil {
		t.Fatalf("unbanned: %v", err)
	}
}
