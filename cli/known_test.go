package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testKnown(t *testing.T) (*knownStore, *bytes.Buffer, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "capm")
	var warn bytes.Buffer
	return newKnownStore(env{credDir: dir}, &warn), &warn, filepath.Join(dir, "known.json")
}

func TestKnownMissingFileIsEmpty(t *testing.T) {
	ks, warn, path := testKnown(t)
	if _, ok := ks.get("https://r.example", "alice", "x"); ok {
		t.Fatal("found a record in an empty state")
	}
	if len(ks.all()) != 0 || warn.Len() != 0 {
		t.Errorf("all=%v warn=%q", ks.all(), warn.String())
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("a read created the file")
	}
}

func TestKnownRoundTripMode0600AndShape(t *testing.T) {
	ks, _, path := testKnown(t)
	when := time.Date(2026, 11, 11, 10, 0, 0, 0, time.UTC)
	err := ks.update("https://r.example", "Alice", "x", func(r *knownRecord) {
		r.OwnerID = 4242
		r.PinnedAt = when
		r.LastRun = &lastRun{Version: "1.0.0", Digest: "sha256:abc", At: when}
	})
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
	if ds, _ := os.Stat(filepath.Dir(path)); ds.Mode().Perm() != 0o700 {
		t.Errorf("dir mode %v", ds.Mode().Perm())
	}
	// A fresh store (a new process) sees it; owner lookup ignores case.
	ks2 := newKnownStore(env{credDir: filepath.Dir(path)}, &bytes.Buffer{})
	r, ok := ks2.get("https://r.example", "alice", "x")
	if !ok || r.OwnerID != 4242 || r.LastRun == nil || r.LastRun.Version != "1.0.0" || r.LastRun.Digest != "sha256:abc" {
		t.Fatalf("got %+v ok=%v", r, ok)
	}
	b, _ := os.ReadFile(path)
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	reg := raw["registries"].(map[string]any)["https://r.example"].(map[string]any)
	rec := reg["alice/x"].(map[string]any)
	if rec["ownerId"].(float64) != 4242 || raw["version"].(float64) != 1 {
		t.Errorf("shape: %s", b)
	}
	// No temp files left in the directory.
	ents, _ := os.ReadDir(filepath.Dir(path))
	if len(ents) != 1 {
		t.Errorf("directory holds %v", ents)
	}
}

func TestKnownCorruptFileWarnsOnceAndIsReplacedOnWrite(t *testing.T) {
	ks, warn, path := testKnown(t)
	os.MkdirAll(filepath.Dir(path), 0o700)
	os.WriteFile(path, []byte("{not json"), 0o600)

	for i := 0; i < 3; i++ {
		if _, ok := ks.get("r", "alice", "x"); ok {
			t.Fatal("record from a corrupt file")
		}
		ks.all()
	}
	if n := strings.Count(warn.String(), "warning"); n != 1 {
		t.Fatalf("want exactly one warning, got %d: %q", n, warn.String())
	}
	if !strings.Contains(warn.String(), "known.json") {
		t.Errorf("warning does not name the file: %q", warn.String())
	}
	if b, _ := os.ReadFile(path); string(b) != "{not json" {
		t.Errorf("reading overwrote the corrupt file: %q", b)
	}
	if err := ks.update("r", "alice", "x", func(r *knownRecord) { r.OwnerID = 1 }); err != nil {
		t.Fatal(err)
	}
	if strings.Count(warn.String(), "warning") != 1 {
		t.Errorf("update warned again: %q", warn.String())
	}
	ks2 := newKnownStore(env{credDir: filepath.Dir(path)}, &bytes.Buffer{})
	if r, ok := ks2.get("r", "alice", "x"); !ok || r.OwnerID != 1 {
		t.Errorf("replacement not written: %+v %v", r, ok)
	}
}

func TestKnownUnknownFieldsPreserved(t *testing.T) {
	ks, _, path := testKnown(t)
	os.MkdirAll(filepath.Dir(path), 0o700)
	in := `{"version":1,"future":{"a":1},"registries":{"r":{"alice/x":{"ownerId":5,"signer":"someone"}}}}`
	os.WriteFile(path, []byte(in), 0o600)
	if err := ks.update("r", "alice", "x", func(r *knownRecord) { r.OwnerID = 6 }); err != nil {
		t.Fatal(err)
	}
	if err := ks.update("r", "bob", "y", func(r *knownRecord) { r.OwnerID = 7 }); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	for _, want := range []string{`"future"`, `"signer"`, `"someone"`, `"ownerId": 6`} {
		if !strings.Contains(string(b), want) && !strings.Contains(strings.ReplaceAll(string(b), `":`, `": `), want) {
			t.Errorf("lost %s:\n%s", want, b)
		}
	}
}

func TestKnownForgetAndAll(t *testing.T) {
	ks, _, _ := testKnown(t)
	ks.update("r1", "bob", "b", func(r *knownRecord) { r.OwnerID = 2 })
	ks.update("r1", "alice", "a", func(r *knownRecord) { r.OwnerID = 1 })
	ks.update("r0", "zed", "z", func(r *knownRecord) { r.OwnerID = 3 })
	all := ks.all()
	if len(all) != 3 || all[0].Registry != "r0" || all[1].Key != "alice/a" || all[2].Key != "bob/b" {
		t.Fatalf("not sorted: %+v", all)
	}
	if ok, err := ks.forget("r1", "ALICE", "a"); !ok || err != nil {
		t.Fatalf("forget: %v %v", ok, err)
	}
	if ok, _ := ks.forget("r1", "alice", "a"); ok {
		t.Error("forgot twice")
	}
	if len(ks.all()) != 2 {
		t.Errorf("after forget: %+v", ks.all())
	}
}

// Concurrent writers: the last one wins, but the file is always complete JSON.
func TestKnownConcurrentWritersNeverLeavePartialFile(t *testing.T) {
	_, _, path := testKnown(t)
	dir := filepath.Dir(path)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	bad := make(chan string, 1)
	go func() { // reader hammering the file
		for {
			select {
			case <-stop:
				return
			default:
			}
			if b, err := os.ReadFile(path); err == nil {
				var v map[string]any
				if json.Unmarshal(b, &v) != nil {
					select {
					case bad <- string(b):
					default:
					}
					return
				}
			}
		}
	}()
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ks := newKnownStore(env{credDir: dir}, &bytes.Buffer{})
			for j := 0; j < 25; j++ {
				if err := ks.update("r", "alice", fmt.Sprintf("b%d", i), func(r *knownRecord) { r.OwnerID = int64(j + 1) }); err != nil {
					t.Error(err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
	close(stop)
	select {
	case b := <-bad:
		t.Fatalf("saw a partial file: %q", b)
	default:
	}
	b, err := os.ReadFile(path)
	var v map[string]any
	if err != nil || json.Unmarshal(b, &v) != nil {
		t.Fatalf("final file invalid: %v %q", err, b)
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("temp files left: %v", ents)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", st.Mode().Perm())
	}
}

func TestKnownNoConfigDir(t *testing.T) {
	var warn bytes.Buffer
	ks := newKnownStore(env{}, &warn)
	if _, ok := ks.get("r", "a", "b"); ok {
		t.Error("record without a store")
	}
	if err := ks.update("r", "a", "b", func(r *knownRecord) {}); err == nil {
		t.Error("update without a config dir must report an error")
	}
}
