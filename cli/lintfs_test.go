package main

import (
	"strings"
	"testing"
)

// Fake credentials are assembled at run time so this file itself never
// contains a full token.
var (
	fakeGH    = "ghp_" + strings.Repeat("a1B2", 9)
	fakeGHPAT = "github_pat_" + strings.Repeat("A1b2C3", 5) + "_x"
	fakeAWS   = "AKIA" + "ABCDEFGH12345678"
	fakeSlack = "xoxb-" + "1234567890-abcdefghij"
	fakeAnth  = "sk-ant-" + "api03-" + strings.Repeat("Zz9_", 8)
	fakePEM   = "-----BEGIN " + "RSA PRIVATE KEY-----"
)

func TestSecretPatterns(t *testing.T) {
	cases := []struct {
		pattern string
		hit     string
		miss    []string
	}{
		{"github-token", "token: " + fakeGH, []string{"ghp_short", "ghp_" + strings.Repeat("a", 20), "the prefix ghp_ is used by GitHub"}},
		{"github-fine-grained-token", "x=" + fakeGHPAT, []string{"github_pat_", "github_pat_abc"}},
		{"aws-access-key-id", "id " + fakeAWS, []string{"AKIA", "AKIA is the prefix of AWS key ids", "AKIAabcdefgh12345678", "AKIAABCDEFGH1234"}},
		{"slack-token", fakeSlack, []string{"xoxb-", "xoxz-1234567890-abcdefghij", "xox-1234567890-abcdefghij"}},
		{"anthropic-api-key", "KEY=" + fakeAnth, []string{"sk-ant-", "sk-ant-short", "sk-other-" + strings.Repeat("a", 30)}},
		{"private-key", fakePEM, []string{"-----BEGIN PUBLIC KEY-----", "-----BEGIN CERTIFICATE-----", "BEGIN PRIVATE KEY without dashes"}},
	}
	seen := map[string]bool{}
	for _, c := range cases {
		seen[c.pattern] = true
		hits := scanSecrets([]byte("line one\n" + c.hit + "\n"))
		if len(hits) != 1 || hits[0].pattern != c.pattern || hits[0].line != 2 {
			t.Errorf("%s: hits %+v", c.pattern, hits)
		}
		for _, m := range c.miss {
			if h := scanSecrets([]byte(m)); len(h) != 0 {
				t.Errorf("%s near-miss %q matched %+v", c.pattern, m, h)
			}
		}
	}
	for _, p := range secretPatterns {
		if !seen[p.name] {
			t.Errorf("pattern %q has no test", p.name)
		}
	}
	if len(secretPatterns) != len(cases) {
		t.Errorf("table has %d patterns, tests cover %d", len(secretPatterns), len(cases))
	}
	// Other private key flavours and a binary file.
	for _, h := range []string{"-----BEGIN PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----"} {
		if len(scanSecrets([]byte(h))) != 1 {
			t.Errorf("%q not detected", h)
		}
	}
	if len(scanSecrets([]byte("\x00\x01"+fakeGH))) != 0 {
		t.Error("binary content should be skipped")
	}
	// One finding per pattern per file, at the first line.
	if h := scanSecrets([]byte(fakeGH + "\n" + fakeGH)); len(h) != 1 || h[0].line != 1 {
		t.Errorf("repeat: %+v", h)
	}
}

func TestCredentialFileNames(t *testing.T) {
	yes := []string{".env", ".env.local", ".env.production", ".ENV", "server.pem", "tls.key", "id_rsa", "id_ed25519", "credentials.json", ".npmrc", ".netrc"}
	no := []string{".env.example", ".env.sample", ".env.template", ".env.EXAMPLE", "env", "environment.md", "keys.md", "key", "id_rsa.pub", "credentials.md", "README.md", "capm.yaml", "monkey.txt"}
	for _, n := range yes {
		if credentialName(n) == "" {
			t.Errorf("%q should look like a credential file", n)
		}
	}
	for _, n := range no {
		if got := credentialName(n); got != "" {
			t.Errorf("%q should not match (%s)", n, got)
		}
	}
}
