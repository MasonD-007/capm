package api

import "testing"

func TestSemverOrdering(t *testing.T) {
	order := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2",
		"1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.9.0", "1.10.0", "2.0.0"}
	for i := range order {
		for j := range order {
			a, ok1 := parseSemver(order[i])
			b, ok2 := parseSemver(order[j])
			if !ok1 || !ok2 {
				t.Fatalf("parse %s %s", order[i], order[j])
			}
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := a.compare(b); got != want {
				t.Errorf("%s vs %s = %d want %d", order[i], order[j], got, want)
			}
		}
	}
	for _, bad := range []string{"1.0", "v1.0.0", "01.0.0", "1.0.0-", "a.b.c", ""} {
		if _, ok := parseSemver(bad); ok {
			t.Errorf("%q should not parse", bad)
		}
	}
}
