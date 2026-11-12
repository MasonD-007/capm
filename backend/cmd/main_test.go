package main

import (
	"strings"
	"testing"
	"time"

	"github.com/MasonD-007/capm/backend/internal/store"
)

func TestParseTokenTTLDays(t *testing.T) {
	day := 24 * time.Hour
	ok := map[string]time.Duration{
		"":    90 * day, // default
		"90":  90 * day,
		"7":   7 * day,
		" 30": 30 * day,
		"0":   0, // never expires
	}
	for in, want := range ok {
		got, err := parseTokenTTLDays(in)
		if err != nil || got != want {
			t.Errorf("%q: %v %v, want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"-1", "abc", "1.5", "9999999999999999999", "36501"} {
		if _, err := parseTokenTTLDays(in); err == nil {
			t.Errorf("%q: expected an error", in)
		}
	}
}

func TestParseQuotaLimits(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	got, err := parseQuotaLimits(env(nil))
	if err != nil || got != store.DefaultLimits() {
		t.Fatalf("defaults: %+v %v", got, err)
	}
	got, err = parseQuotaLimits(env(map[string]string{
		"MAX_USER_BYTES": " 1000 ", "MAX_USER_BUNDLES": "0", "MAX_BUNDLE_VERSIONS": "7", "MAX_TOTAL_BYTES": "5000"}))
	if err != nil || got != (store.Limits{UserBytes: 1000, UserBundles: 0, BundleVersions: 7, TotalBytes: 5000}) {
		t.Fatalf("explicit: %+v %v", got, err)
	}
	for _, key := range []string{"MAX_USER_BYTES", "MAX_USER_BUNDLES", "MAX_BUNDLE_VERSIONS", "MAX_TOTAL_BYTES"} {
		for _, bad := range []string{"-1", "abc", "1.5", "100MiB", "99999999999999999999"} {
			_, err := parseQuotaLimits(env(map[string]string{key: bad}))
			if err == nil || !strings.Contains(err.Error(), key) {
				t.Errorf("%s=%q: err = %v, want an error naming the variable", key, bad, err)
			}
		}
	}
}
