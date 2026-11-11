package store

import (
	"errors"
	"testing"
)

func TestSetYanked(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Publish(1, "alice", "x", "1.0.0", bundle(t, "x", "1.0.0")); err != nil {
		t.Fatal(err)
	}
	if err := s.SetYanked(1, "x", "1.0.0", true); err != nil {
		t.Fatal(err)
	}
	if err := s.SetYanked(1, "x", "1.0.0", true); err != nil { // idempotent
		t.Fatal(err)
	}
	vs, _ := s.Versions("alice", "x")
	if !vs[0].Yanked {
		t.Fatal("not yanked")
	}
	if _, err := s.Blob("alice", "x", "1.0.0"); err != nil {
		t.Fatalf("blob must be retained: %v", err)
	}
	if err := s.SetYanked(1, "x", "1.0.0", false); err != nil {
		t.Fatal(err)
	}
	vs, _ = s.Versions("alice", "x")
	if vs[0].Yanked {
		t.Fatal("still yanked")
	}
	for _, c := range []struct {
		id      int64
		name, v string
	}{{1, "x", "9.9.9"}, {1, "nope", "1.0.0"}, {2, "x", "1.0.0"}} {
		if err := s.SetYanked(c.id, c.name, c.v, true); !errors.Is(err, ErrNotFound) {
			t.Errorf("%+v: %v", c, err)
		}
	}
}
