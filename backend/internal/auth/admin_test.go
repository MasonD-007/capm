package auth

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseAdminIDs(t *testing.T) {
	ok := []struct {
		in   string
		want []int64
	}{
		{"", nil},
		{"   ", nil},
		{"139420415", []int64{139420415}},
		{" 1 , 2,3 ", []int64{1, 2, 3}},
		{"1,,2,", []int64{1, 2}},
		{"7,7", []int64{7}},
	}
	for _, c := range ok {
		got, err := ParseAdminIDs(c.in)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%q: got %v, %v want %v", c.in, got, err, c.want)
		}
	}
	for _, in := range []string{"MasonD-007", "1,abc", "1.5", "0", "-3", "99999999999999999999", "1 2"} {
		_, err := ParseAdminIDs(in)
		if err == nil || !strings.Contains(err.Error(), "ADMIN_GITHUB_IDS") {
			t.Errorf("%q: err = %v, want a clear ADMIN_GITHUB_IDS error", in, err)
		}
	}
}

func TestIsAdmin(t *testing.T) {
	if New(nil, Config{}).IsAdmin(5) {
		t.Fatal("no admins configured: nobody is admin")
	}
	s := New(nil, Config{AdminIDs: []int64{5, 6}})
	if !s.IsAdmin(5) || !s.IsAdmin(6) || s.IsAdmin(7) || s.IsAdmin(0) {
		t.Fatal("IsAdmin wrong")
	}
}
