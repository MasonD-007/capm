package main

import (
	"strings"
	"testing"
)

func lookup(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestParseOIDCDefaultsToGitHub(t *testing.T) {
	c, err := parseOIDC(lookup(nil))
	if err != nil || c == nil {
		t.Fatalf("%+v %v", c, err)
	}
	if c.Issuer != "https://token.actions.githubusercontent.com" ||
		c.JWKSURL != "https://token.actions.githubusercontent.com/.well-known/jwks" ||
		c.Audience != "https://capm.masondrake.dev" {
		t.Fatalf("%+v", c)
	}
}

func TestParseOIDCEmptyIssuerDisables(t *testing.T) {
	for _, v := range []string{"", "  "} {
		c, err := parseOIDC(lookup(map[string]string{"OIDC_ISSUER": v, "OIDC_AUDIENCE": "x"}))
		if err != nil || c != nil {
			t.Fatalf("%q: %+v %v", v, c, err)
		}
	}
}

func TestParseOIDCOverrides(t *testing.T) {
	c, err := parseOIDC(lookup(map[string]string{
		"OIDC_ISSUER":   "https://ghe.example/_services/token",
		"OIDC_JWKS_URL": "https://ghe.example/_services/token/keys",
		"OIDC_AUDIENCE": " https://registry.example ",
	}))
	if err != nil || c.Issuer != "https://ghe.example/_services/token" || c.JWKSURL != "https://ghe.example/_services/token/keys" || c.Audience != "https://registry.example" {
		t.Fatalf("%+v %v", c, err)
	}
	// Loopback http is allowed for tests and local development.
	if _, err := parseOIDC(lookup(map[string]string{"OIDC_JWKS_URL": "http://127.0.0.1:9/jwks"})); err != nil {
		t.Fatal(err)
	}
}

func TestParseOIDCInvalidValuesRefuseToStart(t *testing.T) {
	cases := []map[string]string{
		{"OIDC_ISSUER": "not a url"},
		{"OIDC_ISSUER": "ftp://token.example"},
		{"OIDC_ISSUER": "http://token.example"}, // plain http to a real host
		{"OIDC_ISSUER": "https://u:p@token.example"},
		{"OIDC_ISSUER": "https://token.example/?a=b"},
		{"OIDC_JWKS_URL": "http://keys.example/jwks"},
		{"OIDC_JWKS_URL": "nope"},
		{"OIDC_JWKS_URL": "https://"},
		{"OIDC_AUDIENCE": ""}, // an empty audience must never match
		{"OIDC_AUDIENCE": "   "},
		{"OIDC_AUDIENCE": "two words"},
		{"OIDC_AUDIENCE": "bad\nline"},
		{"OIDC_AUDIENCE": strings.Repeat("a", 300)},
	}
	for _, m := range cases {
		c, err := parseOIDC(lookup(m))
		if err == nil || c != nil {
			t.Errorf("%v: accepted (%+v)", m, c)
			continue
		}
		for k := range m {
			if !strings.Contains(err.Error(), k) {
				t.Errorf("%v: error %q does not name the variable", m, err)
			}
		}
	}
}
