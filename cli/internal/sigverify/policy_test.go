package sigverify

import (
	"errors"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
)

// These tests call checkIdentity directly on certificate values. They are the
// only coverage for certificate shapes the real fixture cannot express (the
// fake CA cannot issue Actions-shaped certificates and no real message
// signature with an Actions identity is available offline), so each rule gets
// a passing and a failing case here, and the real fixture repeats the
// owner/id/repository rules end to end in TestRealBundlePolicy.

const (
	goodSHA = "0123456789abcdef0123456789abcdef01234567"
	goodSAN = "https://github.com/acme/ci/.github/workflows/release.yml@refs/tags/v1.2.3"
)

func goodCert() certificate.Summary {
	return certificate.Summary{
		CertificateIssuer:      "CN=sigstore-intermediate,O=sigstore.dev",
		SubjectAlternativeName: goodSAN,
		Extensions: certificate.Extensions{
			Issuer:                          ActionsIssuer,
			BuildSignerURI:                  goodSAN,
			SourceRepositoryURI:             "https://github.com/acme/app",
			SourceRepositoryIdentifier:      "123456",
			SourceRepositoryOwnerURI:        "https://github.com/acme",
			SourceRepositoryOwnerIdentifier: "4242",
			SourceRepositoryDigest:          goodSHA,
			SourceRepositoryRef:             "refs/tags/v1.2.3",
			RunInvocationURI:                "https://github.com/acme/app/actions/runs/987/attempts/2",
		},
	}
}

func TestCheckIdentityAccepts(t *testing.T) {
	id, err := checkIdentity(goodCert(), Expect{OwnerLogin: "acme", OwnerID: 4242, RepositoryID: 123456, Repository: "acme/app"})
	if err != nil {
		t.Fatal(err)
	}
	want := Identity{
		Issuer: ActionsIssuer, OwnerLogin: "acme", OwnerID: 4242, Repository: "acme/app", RepositoryID: 123456,
		WorkflowRef: goodSAN, SourceRef: "refs/tags/v1.2.3", SourceSHA: goodSHA,
		RunURL: "https://github.com/acme/app/actions/runs/987/attempts/2",
	}
	if id != want {
		t.Errorf("got %+v\nwant %+v", id, want)
	}
}

func TestCheckIdentityRules(t *testing.T) {
	type mod = func(*certificate.Summary)
	cases := []struct {
		name   string
		mod    mod
		want   Expect
		field  string // "" = must pass
		reason string
	}{
		// issuer
		{"issuer exact", nil, Expect{OwnerLogin: "acme"}, "", ""},
		{"issuer other provider", func(c *certificate.Summary) { c.Issuer = "https://accounts.google.com" }, Expect{OwnerLogin: "acme"}, "issuer", "mismatch"},
		{"issuer GitHub login (laptop)", func(c *certificate.Summary) { c.Issuer = "https://github.com/login/oauth" }, Expect{OwnerLogin: "acme"}, "issuer", "mismatch"},
		{"issuer with suffix", func(c *certificate.Summary) { c.Issuer += "/" }, Expect{OwnerLogin: "acme"}, "issuer", "mismatch"},
		{"issuer different case", func(c *certificate.Summary) { c.Issuer = strings.ToUpper(c.Issuer) }, Expect{OwnerLogin: "acme"}, "issuer", "mismatch"},
		{"issuer empty", func(c *certificate.Summary) { c.Issuer = "" }, Expect{OwnerLogin: "acme"}, "issuer", "mismatch"},

		// owner login
		{"owner different case", nil, Expect{OwnerLogin: "ACME"}, "", ""},
		{"owner mismatch", nil, Expect{OwnerLogin: "other"}, "owner login", "mismatch"},
		{"owner is prefix of cert owner", func(c *certificate.Summary) {
			c.SourceRepositoryOwnerURI = "https://github.com/acme-evil"
			c.SourceRepositoryURI = "https://github.com/acme-evil/app"
		}, Expect{OwnerLogin: "acme"}, "owner login", "mismatch"},
		{"cert owner is prefix of owner", nil, Expect{OwnerLogin: "acme-evil"}, "owner login", "mismatch"},
		{"owner URI has a path", func(c *certificate.Summary) { c.SourceRepositoryOwnerURI = "https://github.com/acme/evil" }, Expect{OwnerLogin: "acme"}, "owner login", "malformed"},
		{"owner URI trailing slash", func(c *certificate.Summary) { c.SourceRepositoryOwnerURI = "https://github.com/acme/" }, Expect{OwnerLogin: "acme"}, "owner login", "malformed"},
		{"owner URI query", func(c *certificate.Summary) { c.SourceRepositoryOwnerURI = "https://github.com/acme?x=1" }, Expect{OwnerLogin: "acme"}, "owner login", "malformed"},
		{"owner URI http", func(c *certificate.Summary) { c.SourceRepositoryOwnerURI = "http://github.com/acme" }, Expect{OwnerLogin: "acme"}, "owner login", "malformed"},
		{"owner URI wrong host", func(c *certificate.Summary) { c.SourceRepositoryOwnerURI = "https://github.com.evil.example/acme" }, Expect{OwnerLogin: "acme"}, "owner login", "malformed"},
		{"owner URI other host", func(c *certificate.Summary) { c.SourceRepositoryOwnerURI = "https://gitlab.com/acme" }, Expect{OwnerLogin: "acme"}, "owner login", "malformed"},
		{"owner URI upper-case host", func(c *certificate.Summary) { c.SourceRepositoryOwnerURI = "https://GitHub.com/acme" }, Expect{OwnerLogin: "acme"}, "owner login", "malformed"},
		{"owner URI userinfo", func(c *certificate.Summary) { c.SourceRepositoryOwnerURI = "https://user@github.com/acme" }, Expect{OwnerLogin: "acme"}, "owner login", "malformed"},
		{"owner URI empty", func(c *certificate.Summary) { c.SourceRepositoryOwnerURI = "" }, Expect{OwnerLogin: "acme"}, "owner login", "malformed"},
		{"owner URI with a newline", func(c *certificate.Summary) { c.SourceRepositoryOwnerURI = "https://github.com/acme\n" }, Expect{OwnerLogin: "acme"}, "owner login", "malformed"},
		{"owner URI non-ASCII login", func(c *certificate.Summary) { c.SourceRepositoryOwnerURI = "https://github.com/acmé" }, Expect{OwnerLogin: "acme"}, "owner login", "malformed"},

		// owner id
		{"owner id pinned and equal", nil, Expect{OwnerLogin: "acme", OwnerID: 4242}, "", ""},
		{"owner id pinned but different", nil, Expect{OwnerLogin: "acme", OwnerID: 4243}, "owner id", "mismatch"},
		{"owner id not pinned is not compared", nil, Expect{OwnerLogin: "acme"}, "", ""},
		{"owner id missing", func(c *certificate.Summary) { c.SourceRepositoryOwnerIdentifier = "" }, Expect{OwnerLogin: "acme"}, "owner id", "missing"},
		{"owner id zero", func(c *certificate.Summary) { c.SourceRepositoryOwnerIdentifier = "0" }, Expect{OwnerLogin: "acme"}, "owner id", "malformed"},
		{"owner id negative", func(c *certificate.Summary) { c.SourceRepositoryOwnerIdentifier = "-5" }, Expect{OwnerLogin: "acme"}, "owner id", "malformed"},
		{"owner id plus sign", func(c *certificate.Summary) { c.SourceRepositoryOwnerIdentifier = "+5" }, Expect{OwnerLogin: "acme"}, "owner id", "malformed"},
		{"owner id leading zero", func(c *certificate.Summary) { c.SourceRepositoryOwnerIdentifier = "0042" }, Expect{OwnerLogin: "acme"}, "owner id", "malformed"},
		{"owner id hex", func(c *certificate.Summary) { c.SourceRepositoryOwnerIdentifier = "0x10" }, Expect{OwnerLogin: "acme"}, "owner id", "malformed"},
		{"owner id with space", func(c *certificate.Summary) { c.SourceRepositoryOwnerIdentifier = "42 " }, Expect{OwnerLogin: "acme"}, "owner id", "malformed"},
		{"owner id overflows int64", func(c *certificate.Summary) { c.SourceRepositoryOwnerIdentifier = "9223372036854775808" }, Expect{OwnerLogin: "acme"}, "owner id", "malformed"},
		{"owner id missing even when pinned", func(c *certificate.Summary) { c.SourceRepositoryOwnerIdentifier = "" }, Expect{OwnerLogin: "acme", OwnerID: 4242}, "owner id", "missing"},

		// repository
		{"repository equal, different case", nil, Expect{OwnerLogin: "acme", Repository: "ACME/App"}, "", ""},
		{"repository mismatch", nil, Expect{OwnerLogin: "acme", Repository: "acme/other"}, "repository", "mismatch"},
		{"repository is a prefix", nil, Expect{OwnerLogin: "acme", Repository: "acme/ap"}, "repository", "mismatch"},
		{"repository has a suffix", nil, Expect{OwnerLogin: "acme", Repository: "acme/app2"}, "repository", "mismatch"},
		{"repository not compared when not asked", nil, Expect{OwnerLogin: "acme"}, "", ""},
		{"repository URI missing", func(c *certificate.Summary) { c.SourceRepositoryURI = "" }, Expect{OwnerLogin: "acme"}, "repository", "malformed"},
		{"repository URI no repo", func(c *certificate.Summary) { c.SourceRepositoryURI = "https://github.com/acme" }, Expect{OwnerLogin: "acme"}, "repository", "malformed"},
		{"repository URI extra path", func(c *certificate.Summary) { c.SourceRepositoryURI = "https://github.com/acme/app/tree/main" }, Expect{OwnerLogin: "acme"}, "repository", "malformed"},
		{"repository URI .git", func(c *certificate.Summary) { c.SourceRepositoryURI = "https://github.com/acme/app/" }, Expect{OwnerLogin: "acme"}, "repository", "malformed"},
		{"repository URI dot-dot", func(c *certificate.Summary) { c.SourceRepositoryURI = "https://github.com/acme/.." }, Expect{OwnerLogin: "acme"}, "repository", "malformed"},
		{"repository URI http", func(c *certificate.Summary) { c.SourceRepositoryURI = "http://github.com/acme/app" }, Expect{OwnerLogin: "acme"}, "repository", "malformed"},
		{"repository owner differs from owner URI", func(c *certificate.Summary) { c.SourceRepositoryURI = "https://github.com/evil/app" }, Expect{OwnerLogin: "acme"}, "repository", "inconsistent with owner"},
		{"repository owner case differs only", func(c *certificate.Summary) { c.SourceRepositoryURI = "https://github.com/ACME/app" }, Expect{OwnerLogin: "acme"}, "", ""},

		// repository id
		{"repository id pinned and equal", nil, Expect{OwnerLogin: "acme", RepositoryID: 123456}, "", ""},
		{"repository id pinned but different", nil, Expect{OwnerLogin: "acme", RepositoryID: 123457}, "repository id", "mismatch"},
		{"repository id missing", func(c *certificate.Summary) { c.SourceRepositoryIdentifier = "" }, Expect{OwnerLogin: "acme"}, "repository id", "missing"},
		{"repository id zero", func(c *certificate.Summary) { c.SourceRepositoryIdentifier = "0" }, Expect{OwnerLogin: "acme"}, "repository id", "malformed"},
		{"repository id not a number", func(c *certificate.Summary) { c.SourceRepositoryIdentifier = "abc" }, Expect{OwnerLogin: "acme"}, "repository id", "malformed"},
		{"repository id negative", func(c *certificate.Summary) { c.SourceRepositoryIdentifier = "-1" }, Expect{OwnerLogin: "acme"}, "repository id", "malformed"},

		// SAN / build signer
		{"SAN: reusable workflow in another org is fine", func(c *certificate.Summary) {
			c.SubjectAlternativeName = "https://github.com/capm-actions/publish/.github/workflows/sign.yml@refs/tags/v1"
			c.BuildSignerURI = c.SubjectAlternativeName
		}, Expect{OwnerLogin: "acme"}, "", ""},
		{"SAN: build signer absent, SAN used", func(c *certificate.Summary) { c.BuildSignerURI = "" }, Expect{OwnerLogin: "acme"}, "", ""},
		{"SAN: an email", func(c *certificate.Summary) { c.SubjectAlternativeName = "dev@example.com" }, Expect{OwnerLogin: "acme"}, "workflow", "malformed"},
		{"SAN: not a workflow path", func(c *certificate.Summary) { c.SubjectAlternativeName = "https://github.com/acme/ci" }, Expect{OwnerLogin: "acme"}, "workflow", "malformed"},
		{"SAN: other host", func(c *certificate.Summary) {
			c.SubjectAlternativeName = "https://evil.example/acme/ci/.github/workflows/r.yml@refs/heads/main"
		}, Expect{OwnerLogin: "acme"}, "workflow", "malformed"},
		{"SAN: workflow file in a subdirectory", func(c *certificate.Summary) {
			c.SubjectAlternativeName = "https://github.com/acme/ci/.github/workflows/a/b.yml@refs/heads/main"
		}, Expect{OwnerLogin: "acme"}, "workflow", "malformed"},
		{"SAN: missing ref", func(c *certificate.Summary) {
			c.SubjectAlternativeName = "https://github.com/acme/ci/.github/workflows/r.yml"
		}, Expect{OwnerLogin: "acme"}, "workflow", "malformed"},
		{"build signer present but malformed", func(c *certificate.Summary) { c.BuildSignerURI = "https://evil.example/x" }, Expect{OwnerLogin: "acme"}, "workflow", "malformed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := goodCert()
			if tc.mod != nil {
				tc.mod(&c)
			}
			_, err := checkIdentity(c, tc.want)
			if tc.field == "" {
				if err != nil {
					t.Fatalf("want success, got %v", err)
				}
				return
			}
			var ie *IdentityError
			if !errors.Is(err, ErrIdentity) || !errors.As(err, &ie) {
				t.Fatalf("want ErrIdentity, got %v", err)
			}
			if ie.Field != tc.field || ie.Reason != tc.reason {
				t.Errorf("got field=%q reason=%q, want field=%q reason=%q (%v)", ie.Field, ie.Reason, tc.field, tc.reason, err)
			}
		})
	}
}

// Values from the certificate that fail their shape must never be echoed.
func TestIdentityErrorsDoNotEchoAttackerText(t *testing.T) {
	const evil = "EVIL\x1b[31m-injected\nline"
	fields := map[string]func(c *certificate.Summary){
		"issuer":   func(c *certificate.Summary) { c.Issuer = evil },
		"owner":    func(c *certificate.Summary) { c.SourceRepositoryOwnerURI = "https://github.com/" + evil },
		"ownerid":  func(c *certificate.Summary) { c.SourceRepositoryOwnerIdentifier = evil },
		"repo":     func(c *certificate.Summary) { c.SourceRepositoryURI = "https://github.com/acme/" + evil },
		"repoid":   func(c *certificate.Summary) { c.SourceRepositoryIdentifier = evil },
		"san":      func(c *certificate.Summary) { c.SubjectAlternativeName = evil },
		"build":    func(c *certificate.Summary) { c.BuildSignerURI = evil },
		"repo own": func(c *certificate.Summary) { c.SourceRepositoryURI = "https://github.com/" + evil + "/x" },
	}
	for name, f := range fields {
		c := goodCert()
		f(&c)
		_, err := checkIdentity(c, Expect{OwnerLogin: "acme"})
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		for _, bad := range []string{"\x1b", "\n", "injected"} {
			if strings.Contains(err.Error(), bad) {
				t.Errorf("%s: error echoes attacker text: %q", name, err.Error())
			}
		}
	}
	// A valid but different owner is shown (it passed the GitHub login shape).
	c := goodCert()
	_, err := checkIdentity(c, Expect{OwnerLogin: "other"})
	if err == nil || !strings.Contains(err.Error(), `"acme"`) {
		t.Errorf("a shape-valid owner should be shown: %v", err)
	}
}

func TestIdentityInformationalFieldsAreShapeChecked(t *testing.T) {
	c := goodCert()
	c.SourceRepositoryDigest = "not-a-sha"
	c.RunInvocationURI = "https://evil.example/run"
	c.SourceRepositoryRef = "refs/heads/über\x1b[0m\n" + strings.Repeat("x", 500)
	c.SubjectAlternativeName = "https://github.com/acme/ci/.github/workflows/release.yml@refs/heads/ü\x1b[0m"
	c.BuildSignerURI = ""
	id, err := checkIdentity(c, Expect{OwnerLogin: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if id.SourceSHA != "" || id.RunURL != "" {
		t.Errorf("malformed informational fields surfaced: %+v", id)
	}
	for _, s := range []string{id.SourceRef, id.WorkflowRef} {
		for i := 0; i < len(s); i++ {
			if s[i] < 0x20 || s[i] > 0x7e {
				t.Errorf("non-printable byte in %q", s)
			}
		}
	}
	if len(id.SourceRef) > 210 {
		t.Errorf("SourceRef not truncated: %d", len(id.SourceRef))
	}
	if !strings.HasPrefix(id.WorkflowRef, "https://github.com/acme/ci/.github/workflows/release.yml@refs/heads/") {
		t.Errorf("WorkflowRef = %q", id.WorkflowRef)
	}
}

func TestValidateExpect(t *testing.T) {
	ok := []Expect{
		{OwnerLogin: "a"},
		{OwnerLogin: "Acme-1"},
		{OwnerLogin: "acme", Repository: "acme/app.v2_x"},
		{OwnerLogin: "acme", Repository: "ACME/App"},
	}
	for _, e := range ok {
		if err := validateExpect(e); err != nil {
			t.Errorf("%+v: %v", e, err)
		}
	}
	bad := []Expect{
		{},
		{OwnerLogin: "-acme"},
		{OwnerLogin: "acme-"},
		{OwnerLogin: "ac me"},
		{OwnerLogin: "acme/app"},
		{OwnerLogin: strings.Repeat("a", 40)},
		{OwnerLogin: "Kelvin"}, // Kelvin sign: EqualFold-equal to "k" but not ASCII
		{OwnerLogin: "acme", Repository: "app"},
		{OwnerLogin: "acme", Repository: "acme/"},
		{OwnerLogin: "acme", Repository: "acme/a/b"},
		{OwnerLogin: "acme", Repository: "acme/.."},
		{OwnerLogin: "acme", Repository: "other/app"},
		{OwnerLogin: "acme", OwnerID: -1},
		{OwnerLogin: "acme", RepositoryID: -1},
	}
	for _, e := range bad {
		if err := validateExpect(e); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%+v: want ErrInvalidInput, got %v", e, err)
		}
	}
}

func TestLibraryErrorTextIsSanitised(t *testing.T) {
	err := newErr(ErrUntrusted, "verification failed", errors.New("bad \x1b[31m cert é\nCN="+strings.Repeat("A", 1000)))
	s := err.Error()
	if strings.ContainsAny(s, "\x1b\n") || len(s) > 400 {
		t.Errorf("unsanitised: %q", s)
	}
	if !errors.Is(err, ErrUntrusted) {
		t.Error("kind lost")
	}
}
