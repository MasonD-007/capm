package main

import (
	"strings"
	"testing"
)

func TestParseReportRate(t *testing.T) {
	for in, want := range map[string]int{"": 5, "5": 5, "20": 20, " 3 ": 3, "0": 0} {
		if got, err := parseReportRate(in); err != nil || got != want {
			t.Errorf("%q: %d %v, want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"-1", "abc", "1.5", "99999999999999999999", "100001"} {
		if _, err := parseReportRate(in); err == nil {
			t.Errorf("%q: expected an error", in)
		}
	}
}

func TestParseHTTPURL(t *testing.T) {
	for _, in := range []string{"https://hooks.example.com/T/B/SECRET", "http://127.0.0.1:8080/x", " https://ntfy.sh/topic "} {
		if got, err := parseHTTPURL("REPORT_WEBHOOK_URL", in); err != nil || got != strings.TrimSpace(in) {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
	for _, in := range []string{"ftp://x/y", "hooks.example.com/x", "https:///x", "javascript:alert(1)", "://bad", "file:///etc/passwd"} {
		_, err := parseHTTPURL("REPORT_WEBHOOK_URL", in)
		if err == nil {
			t.Errorf("%q: expected an error", in)
		} else if strings.Contains(err.Error(), in) {
			t.Errorf("error must not echo the value (it may be a secret): %v", err)
		}
	}
	if got, err := parseHTTPURL("X", ""); err != nil || got != "" {
		t.Errorf("empty is allowed: %q %v", got, err)
	}
}
