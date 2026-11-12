package store

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func i64(n int64) *int64 { return &n }

// unlimited is a Limits with every limit disabled, to be narrowed per test.
func unlimited() Limits { return Limits{} }

func quotaStore(t *testing.T, l Limits) *Store {
	t.Helper()
	s := openStore(t)
	s.SetLimits(l)
	return s
}

func asQuota(t *testing.T, err error) *QuotaError {
	t.Helper()
	var qe *QuotaError
	if !errors.As(err, &qe) || !errors.Is(err, ErrQuota) {
		t.Fatalf("want a QuotaError, got %v", err)
	}
	return qe
}

func blobFiles(t *testing.T, s *Store) []string {
	t.Helper()
	es, err := os.ReadDir(s.blobsDir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}

// addSameBytesAs gives owner a second version row for the same blob, the way
// a database can come to hold one (Publish itself ties the manifest to
// name+version, so identical bytes only recur across owners).
func addSameBytesAs(t *testing.T, s *Store, owner int64, name, version, digest string, size int64) {
	t.Helper()
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO users(id, login) VALUES(?, 'u' || ?)`, owner, owner); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO bundles(owner_id, name) VALUES(?,?)`, owner, name); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO versions(owner_id,name,version,digest,manifest,created_at,size) VALUES(?,?,?,?,'{}',1,?)`,
		owner, name, version, digest, size); err != nil {
		t.Fatal(err)
	}
}

func TestPublishAtBytesLimitSucceedsOneByteOverFails(t *testing.T) {
	b1, b2 := bundle(t, "x", "1.0.0"), bundle(t, "x", "1.1.0")
	n := int64(len(b1) + len(b2))

	s := quotaStore(t, Limits{UserBytes: n})
	if err := s.Publish(1, "alice", "x", "1.0.0", b1); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(1, "alice", "x", "1.1.0", b2); err != nil {
		t.Fatalf("exactly at the limit must succeed: %v", err)
	}

	s2 := quotaStore(t, Limits{UserBytes: n - 1})
	if err := s2.Publish(1, "alice", "x", "1.0.0", b1); err != nil {
		t.Fatal(err)
	}
	qe := asQuota(t, s2.Publish(1, "alice", "x", "1.1.0", b2))
	if qe.Limit != LimitUserBytes || qe.Used != int64(len(b1)) || qe.Max != n-1 {
		t.Fatalf("%+v", qe)
	}
	if !strings.Contains(qe.Error(), "storage limit") || !strings.Contains(qe.Error(), "B") {
		t.Fatalf("message should name the limit in human units: %q", qe.Error())
	}
}

func TestQuotaRejectionLeavesNoTraceAndKeepsBlobs(t *testing.T) {
	b1, b2 := bundle(t, "x", "1.0.0"), bundle(t, "x", "1.1.0")
	s := quotaStore(t, Limits{UserBytes: int64(len(b1))})
	if err := s.Publish(1, "alice", "x", "1.0.0", b1); err != nil {
		t.Fatal(err)
	}
	asQuota(t, s.Publish(1, "alice", "x", "1.1.0", b2))
	if got := blobFiles(t, s); len(got) != 1 || got[0] != hexSum(b1) {
		t.Fatalf("blobs after rejection: %v", got)
	}
	vs, _ := s.Versions("alice", "x")
	if len(vs) != 1 {
		t.Fatalf("rejected version was stored: %v", vs)
	}
}

func TestSharedDigestCountedOncePerOwner(t *testing.T) {
	b := bundle(t, "x", "1.0.0")
	n := int64(len(b))
	s := quotaStore(t, Limits{UserBytes: n})
	if err := s.Publish(1, "alice", "x", "1.0.0", b); err != nil {
		t.Fatal(err)
	}
	// Alice already stores these bytes under another name: adds 0 bytes.
	addSameBytesAs(t, s, 1, "x", "9.9.9", "sha256:"+hexSum(b), n)
	u, err := s.Usage(1)
	if err != nil || u.Bytes != n {
		t.Fatalf("usage = %+v %v, want %d bytes (digest counted once)", u, err, n)
	}
	// Bob publishing the same bytes is charged in full for himself...
	if err := s.Publish(2, "bob", "x", "1.0.0", b); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.Usage(2); u.Bytes != n {
		t.Fatalf("bob usage = %d, want %d", u.Bytes, n)
	}
}

func TestPublishingBytesYouAlreadyStoreAddsNoBytesButIsAVersion(t *testing.T) {
	b2 := bundle(t, "x", "1.1.0")
	n := int64(len(b2))
	s := quotaStore(t, Limits{UserBytes: n, BundleVersions: 2})
	// Alice already stores exactly these bytes (and fills her byte limit).
	if err := os.WriteFile(filepath.Join(s.blobsDir, hexSum(b2)), b2, 0o644); err != nil {
		t.Fatal(err)
	}
	addSameBytesAs(t, s, 1, "x", "0.0.1", "sha256:"+hexSum(b2), n)
	if err := s.Publish(1, "alice", "x", "1.1.0", b2); err != nil {
		t.Fatalf("identical bytes add 0 to usage and must pass at the limit: %v", err)
	}
	if u, _ := s.Usage(1); u.Bytes != n {
		t.Fatalf("usage = %d, want %d", u.Bytes, n)
	}
	// ...but it is still a version: the per-bundle limit (2) is now full.
	qe := asQuota(t, s.Publish(1, "alice", "x", "1.2.0", bundle(t, "x", "1.2.0")))
	if qe.Limit != LimitBundleVersions {
		t.Fatalf("%+v", qe)
	}
}

func TestOverLimitUserCanStillAddZeroByteVersionButNotMore(t *testing.T) {
	b := bundle(t, "x", "1.0.0")
	n := int64(len(b))
	s := quotaStore(t, unlimited())
	if err := s.Publish(1, "alice", "x", "1.0.0", b); err != nil {
		t.Fatal(err)
	}
	s.SetLimits(Limits{UserBytes: n - 1}) // now over the limit
	if err := s.Publish(1, "alice", "x", "1.1.0", bundle(t, "x", "1.1.0")); err == nil {
		t.Fatal("an over-limit user must not add bytes")
	} else {
		asQuota(t, err)
	}
}

func TestBundleVersionsLimitCountsYankedAndRemoved(t *testing.T) {
	s := quotaStore(t, Limits{BundleVersions: 3})
	publish(t, s, 1, "alice", "x", "1.0.0")
	publish(t, s, 1, "alice", "x", "1.1.0")
	publish(t, s, 1, "alice", "x", "1.2.0")
	if err := s.SetYanked(1, "x", "1.0.0", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoveVersion(99, "alice", "x", "1.1.0", "bad"); err != nil {
		t.Fatal(err)
	}
	qe := asQuota(t, s.Publish(1, "alice", "x", "2.0.0", bundle(t, "x", "2.0.0")))
	if qe.Limit != LimitBundleVersions || qe.Used != 3 || qe.Max != 3 {
		t.Fatalf("%+v", qe)
	}
	// Another bundle of the same owner has its own count.
	publish(t, s, 1, "alice", "z", "1.0.0")
}

func TestBundlesLimitCountsNamesWithAnyRowAndNewVersionsOfExistingAreFine(t *testing.T) {
	s := quotaStore(t, Limits{UserBundles: 2})
	publish(t, s, 1, "alice", "a", "1.0.0")
	publish(t, s, 1, "alice", "b", "1.0.0")
	if _, err := s.RemoveBundle(99, "alice", "b", "x"); err != nil { // removed rows still hold the name
		t.Fatal(err)
	}
	qe := asQuota(t, s.Publish(1, "alice", "c", "1.0.0", bundle(t, "c", "1.0.0")))
	if qe.Limit != LimitUserBundles || qe.Used != 2 || qe.Max != 2 {
		t.Fatalf("%+v", qe)
	}
	publish(t, s, 1, "alice", "a", "1.1.0") // existing name: not a new bundle
	publish(t, s, 2, "bob", "a", "1.0.0")   // other owners count separately
}

func TestRemovedVersionStopsCountingYankedKeepsCounting(t *testing.T) {
	s := quotaStore(t, unlimited())
	publish(t, s, 1, "alice", "x", "1.0.0")
	publish(t, s, 1, "alice", "x", "1.1.0")
	full, _ := s.Usage(1)
	if err := s.SetYanked(1, "x", "1.0.0", true); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.Usage(1); u.Bytes != full.Bytes {
		t.Fatalf("yanked must still count: %d vs %d", u.Bytes, full.Bytes)
	}
	if _, err := s.RemoveVersion(99, "alice", "x", "1.0.0", "r"); err != nil {
		t.Fatal(err)
	}
	u, _ := s.Usage(1)
	if u.Bytes >= full.Bytes || u.Bytes == 0 || u.Bundles != 1 {
		t.Fatalf("after removal: %+v (was %d)", u, full.Bytes)
	}
}

func TestRemovedVersionWhoseBlobIsKeptByAnotherOwnerDoesNotCount(t *testing.T) {
	s := quotaStore(t, unlimited())
	publish(t, s, 1, "alice", "x", "1.0.0")
	publish(t, s, 2, "bob", "x", "1.0.0") // identical bytes: one blob
	if _, err := s.RemoveVersion(99, "alice", "x", "1.0.0", "r"); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.Usage(1); u.Bytes != 0 {
		t.Fatalf("alice removed it: %d", u.Bytes)
	}
	if u, _ := s.Usage(2); u.Bytes == 0 {
		t.Fatal("bob still stores it")
	}
}

func TestTotalLimitStopsPublishesNamesNoNumbersAndLogsWarn(t *testing.T) {
	b1 := bundle(t, "x", "1.0.0")
	s := quotaStore(t, Limits{TotalBytes: int64(len(b1))})
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	if err := s.Publish(1, "alice", "x", "1.0.0", b1); err != nil {
		t.Fatal(err)
	}
	qe := asQuota(t, s.Publish(2, "bob", "y", "1.0.0", bundle(t, "y", "1.0.0")))
	if qe.Limit != LimitTotalBytes {
		t.Fatalf("%+v", qe)
	}
	if strings.ContainsAny(qe.Error(), "0123456789") {
		t.Fatalf("message must not disclose registry numbers: %q", qe.Error())
	}
	if !strings.Contains(qe.Error(), "full") || !strings.Contains(qe.Error(), "operator") {
		t.Fatalf("message: %q", qe.Error())
	}
	if !strings.Contains(buf.String(), "WARN") || !strings.Contains(buf.String(), "total_bytes") {
		t.Fatalf("expected one warn line, log = %q", buf.String())
	}
	if strings.Count(buf.String(), "WARN") != 1 {
		t.Fatalf("want exactly one warn per rejection: %q", buf.String())
	}
	// Bytes the registry already stores add nothing: bob's copy of x@1.0.0 fits.
	if err := s.Publish(2, "bob", "x", "1.0.0", b1); err != nil {
		t.Fatalf("a publish adding 0 registry bytes must pass: %v", err)
	}
}

func TestOverrideReplacesDefaultsPerUser(t *testing.T) {
	b1, b2 := bundle(t, "x", "1.0.0"), bundle(t, "x", "1.1.0")
	s := quotaStore(t, Limits{UserBytes: int64(len(b1)), UserBundles: 1})
	if err := s.Publish(1, "alice", "x", "1.0.0", b1); err != nil {
		t.Fatal(err)
	}
	asQuota(t, s.Publish(1, "alice", "x", "1.1.0", b2))

	if err := s.SetQuotaOverride(99, 1, i64(1<<20), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.Publish(1, "alice", "x", "1.1.0", b2); err != nil {
		t.Fatalf("override should raise the bytes limit: %v", err)
	}
	// The bundles limit was not overridden: still the default of 1.
	asQuota(t, s.Publish(1, "alice", "y", "1.0.0", bundle(t, "y", "1.0.0")))
	u, _ := s.Usage(1)
	if u.MaxBytes != 1<<20 || !u.BytesOverridden || u.MaxBundles != 1 || u.BundlesOverridden {
		t.Fatalf("%+v", u)
	}
	// Bob is unaffected.
	if u, _ := s.Usage(2); u.MaxBytes != int64(len(b1)) || u.BytesOverridden {
		t.Fatalf("bob %+v", u)
	}
	// Setting both, then clearing both.
	if err := s.SetQuotaOverride(99, 1, i64(1<<20), i64(5)); err != nil {
		t.Fatal(err)
	}
	publish(t, s, 1, "alice", "y", "1.0.0")
	if err := s.SetQuotaOverride(99, 1, nil, nil); err != nil {
		t.Fatal(err)
	}
	u, _ = s.Usage(1)
	if u.BytesOverridden || u.BundlesOverridden || u.MaxBytes != int64(len(b1)) {
		t.Fatalf("cleared: %+v", u)
	}
	var n int
	s.db.QueryRow(`SELECT count(*) FROM quota_overrides`).Scan(&n)
	if n != 0 {
		t.Fatalf("empty override row kept: %d", n)
	}
}

func TestOverrideIsAuditedAndValidated(t *testing.T) {
	s := quotaStore(t, unlimited())
	if err := s.SetQuotaOverride(99, 1, i64(-1), nil); err == nil {
		t.Fatal("negative limit must be refused")
	}
	if err := s.SetQuotaOverride(99, 7, i64(100), i64(3)); err != nil {
		t.Fatal(err)
	}
	log, _ := s.AdminLog(5)
	if len(log) != 1 || log[0].Action != "set_quota" || log[0].Target != "user:7" || log[0].AdminID != 99 ||
		!strings.Contains(log[0].Reason, "100") {
		t.Fatalf("%+v", log)
	}
}

func TestZeroDisablesEachLimit(t *testing.T) {
	s := quotaStore(t, Limits{})
	for i := 0; i < 5; i++ {
		publish(t, s, 1, "alice", fmt.Sprintf("b%d", i), "1.0.0")
		publish(t, s, 1, "alice", "b0", fmt.Sprintf("1.%d.0", i+1))
	}
	// An override of 0 also means unlimited for that user.
	s.SetLimits(Limits{UserBytes: 1})
	if err := s.SetQuotaOverride(99, 1, i64(0), nil); err != nil {
		t.Fatal(err)
	}
	publish(t, s, 1, "alice", "late", "1.0.0")
}

func TestDuplicateVersionBeatsQuota(t *testing.T) {
	s := quotaStore(t, Limits{BundleVersions: 1, UserBundles: 1})
	publish(t, s, 1, "alice", "x", "1.0.0")
	err := s.Publish(1, "alice", "x", "1.0.0", bundle(t, "x", "1.0.0"))
	if !errors.Is(err, ErrVersionExists) {
		t.Fatalf("want ErrVersionExists, got %v", err)
	}
}

func TestInvalidBundleBeatsQuota(t *testing.T) {
	s := quotaStore(t, Limits{UserBundles: 1})
	publish(t, s, 1, "alice", "x", "1.0.0")
	err := s.Publish(1, "alice", "y", "1.0.0", []byte("junk"))
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}

// Many publishes race for the one remaining slot; the check and the insert
// share a transaction on the single connection, so exactly one wins.
func TestConcurrentPublishesCannotExceedLimit(t *testing.T) {
	const racers = 8
	versions := make([]string, racers)
	tars := make([][]byte, racers)
	var maxLen int
	for i := range versions {
		versions[i] = fmt.Sprintf("1.0.%d", i)
		tars[i] = bundle(t, "x", versions[i])
		maxLen = max(maxLen, len(tars[i]))
	}
	cases := map[string]Limits{
		"bundle_versions": {BundleVersions: 1},
		"user_bytes":      {UserBytes: int64(maxLen)}, // two never fit: each tarball is over half of it
		"user_bundles":    {UserBundles: 1},
		"total_bytes":     {TotalBytes: int64(maxLen)},
	}
	for name, lim := range cases {
		t.Run(name, func(t *testing.T) {
			s := quotaStore(t, lim)
			names := make([]string, racers)
			for i := range names {
				names[i] = "x"
				if name == "user_bundles" {
					names[i] = fmt.Sprintf("x%d", i)
				}
			}
			var wg sync.WaitGroup
			errs := make([]error, racers)
			start := make(chan struct{})
			for i := 0; i < racers; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					tb := tars[i]
					if name == "user_bundles" {
						tb = bundle(t, names[i], versions[i])
					}
					errs[i] = s.Publish(1, "alice", names[i], versions[i], tb)
				}()
			}
			close(start)
			wg.Wait()
			ok := 0
			for _, e := range errs {
				switch {
				case e == nil:
					ok++
				case errors.Is(e, ErrQuota):
				default:
					t.Fatalf("unexpected error: %v", e)
				}
			}
			if ok != 1 {
				t.Fatalf("%d publishes succeeded, want exactly 1", ok)
			}
			var rows int
			s.db.QueryRow(`SELECT count(*) FROM versions`).Scan(&rows)
			if rows != 1 || len(blobFiles(t, s)) != 1 {
				t.Fatalf("rows=%d blobs=%v", rows, blobFiles(t, s))
			}
		})
	}
}

func TestDefaultLimits(t *testing.T) {
	d := DefaultLimits()
	if d.UserBytes != 100<<20 || d.UserBundles != 50 || d.BundleVersions != 200 || d.TotalBytes != 3<<30 {
		t.Fatalf("%+v", d)
	}
	s, _ := open(t)
	if s.limits != d {
		t.Fatalf("a fresh store must start with the defaults, got %+v", s.limits)
	}
}

func TestUsageGlobalIsDistinctDigests(t *testing.T) {
	s := quotaStore(t, unlimited())
	publish(t, s, 1, "alice", "x", "1.0.0")
	publish(t, s, 2, "bob", "x", "1.0.0") // same bytes
	publish(t, s, 2, "bob", "y", "1.0.0")
	tot, err := s.TotalBytes()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := s.Usage(1)
	b, _ := s.Usage(2)
	if tot != b.Bytes || a.Bytes >= b.Bytes {
		t.Fatalf("total=%d alice=%d bob=%d", tot, a.Bytes, b.Bytes)
	}
	// Sizes in the table match what is on disk.
	var disk int64
	for _, f := range blobFiles(t, s) {
		fi, _ := os.Stat(filepath.Join(s.blobsDir, f))
		disk += fi.Size()
	}
	if disk != tot {
		t.Fatalf("disk %d vs accounted %d", disk, tot)
	}
}

func TestHumanBytes(t *testing.T) {
	for in, want := range map[int64]string{0: "0 B", 1023: "1023 B", 1024: "1.0 KiB", 100 << 20: "100.0 MiB", 3 << 30: "3.0 GiB", 1536: "1.5 KiB"} {
		if got := HumanBytes(in); got != want {
			t.Errorf("HumanBytes(%d) = %q, want %q", in, got, want)
		}
	}
}
