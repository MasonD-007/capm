package main

import (
	"testing"
	"time"
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
