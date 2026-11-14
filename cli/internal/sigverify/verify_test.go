package sigverify

import (
	"crypto/sha256"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
)

// ---- the real Actions fixture, end to end (real Fulcio chain, SCT, Rekor
// inclusion proof and SET, signature over the artifact digest) ---------------

func TestRealBundleVerifies(t *testing.T) {
	v := realVerifier(t)
	id, err := v.verifyBytes(readFixture(t, fixtureActions), fixtureDigest(t), actionsExpect())
	if err != nil {
		t.Fatal(err)
	}
	want := Identity{
		Issuer:       ActionsIssuer,
		OwnerLogin:   "sigstore",
		OwnerID:      71096353,
		Repository:   "sigstore/sigstore-js",
		RepositoryID: 495574555,
		WorkflowRef:  "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main",
		SourceRef:    "refs/heads/main",
		SourceSHA:    "f0b49a04e5a62250e0f60fb128004a73110fe311",
		RunURL:       "https://github.com/sigstore/sigstore-js/actions/runs/5904696764/attempts/1",
	}
	if id.SignedAt.IsZero() || id.SignedAt.Year() != 2023 {
		t.Errorf("SignedAt = %v", id.SignedAt)
	}
	id.SignedAt = time.Time{}
	if id != want {
		t.Errorf("identity\n got %+v\nwant %+v", id, want)
	}
}

// The fixture's real identity against every expectation, both directions.
func TestRealBundlePolicy(t *testing.T) {
	cases := []struct {
		name    string
		want    Expect
		ok      bool
		kind    error
		field   string
		reason  string
		invalid bool // rejected as ErrInvalidInput before verification
	}{
		{name: "right owner", want: Expect{OwnerLogin: "sigstore"}, ok: true},
		{name: "owner, different case", want: Expect{OwnerLogin: "SigStore"}, ok: true},
		{name: "owner + owner id", want: Expect{OwnerLogin: "sigstore", OwnerID: 71096353}, ok: true},
		{name: "owner + repo id", want: Expect{OwnerLogin: "sigstore", RepositoryID: 495574555}, ok: true},
		{name: "owner + repository", want: Expect{OwnerLogin: "sigstore", Repository: "sigstore/sigstore-js"}, ok: true},
		{name: "repository, different case", want: Expect{OwnerLogin: "sigstore", Repository: "SIGSTORE/Sigstore-JS"}, ok: true},
		{name: "everything", want: Expect{OwnerLogin: "sigstore", OwnerID: 71096353, RepositoryID: 495574555, Repository: "sigstore/sigstore-js"}, ok: true},

		{name: "wrong owner", want: Expect{OwnerLogin: "evil"}, field: "owner login", reason: "mismatch"},
		{name: "prefix of owner", want: Expect{OwnerLogin: "sig"}, field: "owner login", reason: "mismatch"},
		{name: "owner is a prefix of the wanted login", want: Expect{OwnerLogin: "sigstore-evil"}, field: "owner login", reason: "mismatch"},
		{name: "owner with suffix", want: Expect{OwnerLogin: "sigstores"}, field: "owner login", reason: "mismatch"},
		{name: "owner with path suffix", want: Expect{OwnerLogin: "sigstore/evil"}, invalid: true},
		{name: "owner with leading slash", want: Expect{OwnerLogin: "/sigstore"}, invalid: true},
		{name: "owner given as URL", want: Expect{OwnerLogin: "https://github.com/sigstore"}, invalid: true},
		{name: "empty owner", want: Expect{}, invalid: true},
		{name: "right owner, wrong owner id", want: Expect{OwnerLogin: "sigstore", OwnerID: 71096354}, field: "owner id", reason: "mismatch"},
		{name: "right owner, wrong repository id", want: Expect{OwnerLogin: "sigstore", RepositoryID: 495574556}, field: "repository id", reason: "mismatch"},
		{name: "right owner, wrong repository", want: Expect{OwnerLogin: "sigstore", Repository: "sigstore/other"}, field: "repository", reason: "mismatch"},
		{name: "repository with a different owner", want: Expect{OwnerLogin: "sigstore", Repository: "evil/sigstore-js"}, invalid: true},
		{name: "repository prefix", want: Expect{OwnerLogin: "sigstore", Repository: "sigstore/sigstore"}, field: "repository", reason: "mismatch"},
		{name: "negative owner id", want: Expect{OwnerLogin: "sigstore", OwnerID: -1}, invalid: true},
	}
	v := realVerifier(t)
	raw := readFixture(t, fixtureActions)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.verifyBytes(raw, fixtureDigest(t), tc.want)
			switch {
			case tc.ok:
				if err != nil {
					t.Fatalf("want success, got %v", err)
				}
			case tc.invalid:
				if !errors.Is(err, ErrInvalidInput) {
					t.Fatalf("want ErrInvalidInput, got %v", err)
				}
			default:
				var ie *IdentityError
				if !errors.Is(err, ErrIdentity) || !errors.As(err, &ie) {
					t.Fatalf("want ErrIdentity, got %v", err)
				}
				if ie.Field != tc.field || ie.Reason != tc.reason {
					t.Errorf("IdentityError = %+v, want field %q reason %q", ie, tc.field, tc.reason)
				}
			}
		})
	}
}

func TestRealBundleWrongDigest(t *testing.T) {
	d := fixtureDigest(t)
	d[0] ^= 1
	_, err := realVerifier(t).verifyBytes(readFixture(t, fixtureActions), d, actionsExpect())
	if !errors.Is(err, ErrUntrusted) {
		t.Fatalf("want ErrUntrusted, got %v", err)
	}
}

// Tampering with each part of the bundle must fail. As the spike found, the
// log entry commits to the signature and the certificate, so most of these
// are caught by the transparency-log check rather than by the raw signature
// check; the digest case exercises the signature check itself. The test
// records which kind caught each one.
func TestRealBundleTamper(t *testing.T) {
	raw := readFixture(t, fixtureActions)
	v := realVerifier(t)
	if _, err := v.verifyBytes(raw, fixtureDigest(t), actionsExpect()); err != nil {
		t.Fatalf("control: %v", err)
	}
	cases := map[string]func(m map[string]any){
		"signature": func(m map[string]any) {
			flipBase64(t, m, "dsseEnvelope", "signatures", 0, "sig")
		},
		"certificate": func(m map[string]any) {
			flipBase64(t, m, "verificationMaterial", "x509CertificateChain", "certificates", 0, "rawBytes")
		},
		"inclusion proof root hash": func(m map[string]any) {
			flipBase64(t, m, "verificationMaterial", "tlogEntries", 0, "inclusionProof", "rootHash")
		},
		"inclusion proof hash": func(m map[string]any) {
			flipBase64(t, m, "verificationMaterial", "tlogEntries", 0, "inclusionProof", "hashes", 0)
		},
		"signed entry timestamp": func(m map[string]any) {
			flipBase64(t, m, "verificationMaterial", "tlogEntries", 0, "inclusionPromise", "signedEntryTimestamp")
		},
		"log entry body": func(m map[string]any) {
			flipBase64(t, m, "verificationMaterial", "tlogEntries", 0, "canonicalizedBody")
		},
		"payload (statement)": func(m map[string]any) {
			flipBase64(t, m, "dsseEnvelope", "payload")
		},
		"integrated time": func(m map[string]any) {
			setPath(t, m, "1692374736", "verificationMaterial", "tlogEntries", 0, "integratedTime")
		},
		"tlog entry removed": func(m map[string]any) {
			setPath(t, m, []any{}, "verificationMaterial", "tlogEntries")
		},
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			bad := mutate(t, raw, f)
			if sameBytes(bad, raw) {
				t.Fatal("mutation changed nothing")
			}
			_, err := v.verifyBytes(bad, fixtureDigest(t), actionsExpect())
			if err == nil {
				t.Fatal("tampered bundle accepted")
			}
			if !errors.Is(err, ErrUntrusted) && !errors.Is(err, ErrMalformed) {
				t.Fatalf("unexpected kind: %v", err)
			}
			t.Logf("rejected as: %v", err)
		})
	}
}

// ---- shape: what the production profile and the shape checks refuse --------

func TestProductionRejectsFixture(t *testing.T) {
	// The fixture is a v0.1 DSSE attestation: not what capm signs.
	_, err := Verify(readFixture(t, fixtureActions), make([]byte, 32), actionsExpect())
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("want ErrMalformed, got %v", err)
	}
}

func TestShapeRejections(t *testing.T) {
	raw := readFixture(t, fixtureActions)
	v := realVerifier(t)
	d := fixtureDigest(t)
	cases := []struct {
		name string
		raw  []byte
	}{
		{"two signatures", readFixture(t, fixtureTwoSigs)},
		{"public key material", readFixture(t, fixturePublicKey)},
		{"unknown media type", mutate(t, raw, func(m map[string]any) {
			m["mediaType"] = "application/vnd.dev.sigstore.bundle.v9.9+json"
		})},
		{"not a bundle media type", mutate(t, raw, func(m map[string]any) { m["mediaType"] = "text/plain" })},
		{"two log entries", mutate(t, raw, func(m map[string]any) {
			e := path(t, m, "verificationMaterial", "tlogEntries", 0)
			setPath(t, m, []any{e, e}, "verificationMaterial", "tlogEntries")
		})},
		{"empty", []byte{}},
		{"null", []byte("null")},
		{"not json", []byte("\x00\x01garbage")},
		{"empty object", []byte("{}")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := v.verifyBytes(tc.raw, d, actionsExpect())
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("want ErrMalformed, got %v", err)
			}
		})
	}
}

func TestInputLimits(t *testing.T) {
	raw := readFixture(t, fixtureActions)
	v := realVerifier(t)

	// over 64 KiB is refused before parsing
	big := append(append([]byte(nil), raw...), make([]byte, MaxBundleSize)...)
	if _, err := v.verifyBytes(big, fixtureDigest(t), actionsExpect()); !errors.Is(err, ErrMalformed) || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversize: %v", err)
	}
	exact := make([]byte, MaxBundleSize)
	copy(exact, "{}")
	if _, err := v.verifyBytes(exact, fixtureDigest(t), actionsExpect()); errors.Is(err, ErrInvalidInput) || strings.Contains(err.Error(), "larger than") {
		t.Fatalf("a bundle of exactly the limit must reach the parser: %v", err)
	}

	// digest must be exactly 32 bytes in production
	for _, n := range []int{0, 1, 31, 33, 64} {
		_, err := Verify(raw, make([]byte, n), actionsExpect())
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("digest of %d bytes: want ErrInvalidInput, got %v", n, err)
		}
	}
	if _, err := Verify(raw, nil, actionsExpect()); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("nil digest: %v", err)
	}
	// and Expect is validated
	if _, err := Verify(raw, make([]byte, 32), Expect{}); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("empty Expect: %v", err)
	}
}

// ---- stale trust root ---------------------------------------------------------

func TestStaleTrustRoot(t *testing.T) {
	raw := readFixture(t, fixtureActions)
	d := fixtureDigest(t)

	ended := "2024-01-01T00:00:00Z"
	endAll := func(m map[string]any) {
		for _, l := range path(t, m, "tlogs").([]any) {
			setPath(t, l, map[string]any{"start": "2021-01-01T00:00:00Z", "end": ended}, "publicKey", "validFor")
		}
		for _, c := range path(t, m, "certificateAuthorities").([]any) {
			setPath(t, c, map[string]any{"start": "2021-01-01T00:00:00Z", "end": ended}, "validFor")
		}
	}
	cases := []struct {
		name   string
		mutate func(m map[string]any)
		stale  bool
	}{
		{"unmodified embedded root", func(m map[string]any) {}, false},
		// What the spike observed: a root that merely lacks newer entries still
		// verifies a signature made under the entries it has.
		{"only the original Rekor log", func(m map[string]any) {
			setPath(t, m, path(t, m, "tlogs").([]any)[:1], "tlogs")
		}, false},
		{"only the original Fulcio CA is dropped", func(m map[string]any) {
			setPath(t, m, path(t, m, "certificateAuthorities").([]any)[1:], "certificateAuthorities")
		}, false},
		{"no Rekor log at all (truncated)", func(m map[string]any) { setPath(t, m, []any{}, "tlogs") }, true},
		{"only a newer Rekor log (this log unknown)", func(m map[string]any) {
			setPath(t, m, path(t, m, "tlogs").([]any)[1:], "tlogs")
		}, true},
		{"no Fulcio CA at all", func(m map[string]any) { setPath(t, m, []any{}, "certificateAuthorities") }, true},
		{"only the retired Fulcio CA", func(m map[string]any) {
			setPath(t, m, path(t, m, "certificateAuthorities").([]any)[:1], "certificateAuthorities")
		}, true},
		{"every log and CA window ended before today", endAll, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := realVerifier(t)
			v.tr = mustMarshalRoot(t, tc.mutate)
			_, err := v.verifyBytes(raw, d, actionsExpect())
			var se *StaleTrustRootError
			isStale := errors.Is(err, ErrStaleTrustRoot) && errors.As(err, &se)
			if tc.stale != isStale {
				t.Fatalf("stale = %v, want %v (err: %v)", isStale, tc.stale, err)
			}
			if !tc.stale && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.stale {
				if errors.Is(err, ErrUntrusted) || errors.Is(err, ErrIdentity) {
					t.Errorf("stale error must be distinct: %v", err)
				}
				t.Logf("%v", err)
			}
		})
	}
}

// The root's age is judged against the clock the verifier is given: the same
// embedded root is current today and stale in a future where its open-ended
// entries are still open but a (simulated) retirement has happened.
func TestStaleByCurrentTime(t *testing.T) {
	v := realVerifier(t)
	v.tr = mustMarshalRoot(t, func(m map[string]any) {
		// Retire everything at a fixed date in the future of the fixture.
		end := "2030-01-01T00:00:00Z"
		for _, l := range path(t, m, "tlogs").([]any) {
			setPath(t, l, map[string]any{"start": "2021-01-01T00:00:00Z", "end": end}, "publicKey", "validFor")
		}
		for _, c := range path(t, m, "certificateAuthorities").([]any) {
			setPath(t, c, map[string]any{"start": "2021-01-01T00:00:00Z", "end": end}, "validFor")
		}
	})
	raw, d := readFixture(t, fixtureActions), fixtureDigest(t)
	v.now = func() time.Time { return time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC) }
	if _, err := v.verifyBytes(raw, d, actionsExpect()); err != nil {
		t.Fatalf("before retirement: %v", err)
	}
	v.now = func() time.Time { return time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC) }
	if _, err := v.verifyBytes(raw, d, actionsExpect()); !errors.Is(err, ErrStaleTrustRoot) {
		t.Fatalf("after retirement: want ErrStaleTrustRoot, got %v", err)
	}
}

// A log time in the future is refused, not trusted.
func TestFutureSignatureRefused(t *testing.T) {
	v := realVerifier(t)
	v.now = func() time.Time { return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC) }
	_, err := v.verifyBytes(readFixture(t, fixtureActions), fixtureDigest(t), actionsExpect())
	if !errors.Is(err, ErrUntrusted) || !strings.Contains(err.Error(), "system clock") {
		t.Fatalf("got %v", err)
	}
}

// ---- sigstore-go's in-memory Sigstore: message signatures, v0.3 -------------
//
// The fake CA issues email-SAN certificates with only the legacy issuer
// extension, and its certificates carry no SCT, so: the identity policy
// cannot be satisfied (it is replaced by a pass-through for the crypto cases
// and exercised for real in the last case, where it must refuse), and SCTs
// are not required.

func virtualVerifier(vs *ca.VirtualSigstore) *verifier {
	return &verifier{
		tr:      vs,
		now:     time.Now,
		profile: profile{alg: "sha256", digestLen: 32, versions: []string{"v0.3"}},
		policy: func(c certificate.Summary, _ Expect) (Identity, error) {
			return Identity{Issuer: c.Issuer}, nil
		},
	}
}

func TestVirtualSigstoreMessageSignature(t *testing.T) {
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	artifact := []byte("pretend tarball bytes")
	sum := sha256.Sum256(artifact)
	ent, err := vs.Sign("dev@example.com", "https://github.com/login/oauth", artifact)
	if err != nil {
		t.Fatal(err)
	}
	v := virtualVerifier(vs)
	want := Expect{OwnerLogin: "acme"}

	if _, err := v.verifyEntity(ent, sum[:], want); err != nil {
		t.Fatalf("valid: %v", err)
	}

	t.Run("wrong digest", func(t *testing.T) {
		bad := sum
		bad[31] ^= 1
		if _, err := v.verifyEntity(ent, bad[:], want); !errors.Is(err, ErrUntrusted) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("certificate from another CA", func(t *testing.T) {
		evil, _ := ca.NewVirtualSigstore()
		ent2, _ := evil.Sign("dev@example.com", "https://github.com/login/oauth", artifact)
		_, err := v.verifyEntity(ent2, sum[:], want)
		if err == nil {
			t.Fatal("accepted a certificate from a CA that is not in the trusted material")
		}
		// An unknown CA and a rotated CA are indistinguishable offline.
		if !errors.Is(err, ErrStaleTrustRoot) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("log entry from another log", func(t *testing.T) {
		other, _ := ca.NewVirtualSigstore()
		ent2, _ := other.Sign("dev@example.com", "https://github.com/login/oauth", artifact)
		_, err := v.verifyEntity(ent2, sum[:], want)
		if !errors.Is(err, ErrStaleTrustRoot) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("signed in the future", func(t *testing.T) {
		ent2, _ := vs.SignAtTime("dev@example.com", "https://github.com/login/oauth", artifact, time.Now().Add(time.Hour))
		if _, err := v.verifyEntity(ent2, sum[:], want); !errors.Is(err, ErrUntrusted) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("certificate expired at the logged time", func(t *testing.T) {
		ent2, _ := vs.SignAtTime("dev@example.com", "https://github.com/login/oauth", artifact, time.Now().Add(-30*time.Minute))
		if _, err := v.verifyEntity(ent2, sum[:], want); !errors.Is(err, ErrUntrusted) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("wrong bundle version", func(t *testing.T) {
		ent2, _ := vs.SignWithVersion("dev@example.com", "https://github.com/login/oauth", artifact, "v0.2")
		if _, err := v.verifyEntity(ent2, sum[:], want); !errors.Is(err, ErrMalformed) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("DSSE refused in the production shape", func(t *testing.T) {
		env, _ := vs.Attest("dev@example.com", "https://github.com/login/oauth", []byte(`{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"x","predicate":{}}`))
		if _, err := v.verifyEntity(env, sum[:], want); !errors.Is(err, ErrMalformed) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("real policy refuses a non-Actions certificate with valid crypto", func(t *testing.T) {
		pv := virtualVerifier(vs)
		pv.policy = checkIdentity
		_, err := pv.verifyEntity(ent, sum[:], want)
		var ie *IdentityError
		if !errors.Is(err, ErrIdentity) || !errors.As(err, &ie) || ie.Field != "issuer" {
			t.Fatalf("got %v", err)
		}
	})
}

// ---- concurrency -----------------------------------------------------------------

func TestConcurrentUse(t *testing.T) {
	raw, d := readFixture(t, fixtureActions), fixtureDigest(t)
	v := realVerifier(t)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 3; j++ {
				if _, err := v.verifyBytes(raw, d, actionsExpect()); err != nil {
					t.Error(err)
				}
				// and the exported entry point, which must refuse this fixture every time
				if _, err := Verify(raw, make([]byte, 32), actionsExpect()); !errors.Is(err, ErrMalformed) {
					t.Error(err)
				}
			}
		}(i)
	}
	wg.Wait()
}
