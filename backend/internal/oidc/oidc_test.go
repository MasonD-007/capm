package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	testIssuer   = "https://token.actions.githubusercontent.com"
	testAudience = "https://capm.example.test"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func genKey(t testing.TB, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// jwk renders a public key the way GitHub's JWKS does.
func jwk(kid string, pub *rsa.PublicKey, extra map[string]any) map[string]any {
	m := map[string]any{
		"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
		"n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes()),
	}
	for k, v := range extra {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return m
}

// fakeJWKS serves a mutable key set and counts requests.
type fakeJWKS struct {
	mu    sync.Mutex
	keys  []map[string]any
	down  bool
	extra int // bytes of padding appended to the body
	hits  atomic.Int32
	srv   *httptest.Server
}

func newFakeJWKS(t testing.TB, keys ...map[string]any) *fakeJWKS {
	f := &fakeJWKS{keys: keys}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.hits.Add(1)
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.down {
			http.Error(w, "down", 500)
			return
		}
		b, _ := json.Marshal(map[string]any{"keys": f.keys})
		w.Write(b)
		w.Write([]byte(strings.Repeat(" ", f.extra)))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeJWKS) set(down bool, keys ...map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
	if keys != nil {
		f.keys = keys
	}
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type fixture struct {
	key  *rsa.PrivateKey
	kid  string
	jwks *fakeJWKS
	clk  *clock
	v    *Verifier
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	key := genKey(t, 2048)
	f := &fixture{key: key, kid: "kid-1", clk: &clock{t: time.Unix(1_800_000_000, 0)}}
	f.jwks = newFakeJWKS(t, jwk(f.kid, &key.PublicKey, nil))
	f.v = New(Config{Issuer: testIssuer, Audience: testAudience, JWKSURL: f.jwks.srv.URL + "/.well-known/jwks", Now: f.clk.now})
	return f
}

func (f *fixture) claims(over map[string]any) map[string]any {
	now := f.clk.now().Unix()
	c := map[string]any{
		"iss": testIssuer, "aud": testAudience, "jti": "jti-" + fmt.Sprint(now, rand.Reader != nil, time.Now().UnixNano()),
		"iat": now, "nbf": now - 5, "exp": now + 600,
		"repository": "alice/x", "repository_owner": "alice", "repository_owner_id": "42",
	}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return c
}

func signWith(t testing.TB, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	in := b64(hb) + "." + b64(cb)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + b64(sig)
}

func (f *fixture) token(t testing.TB, over map[string]any) string {
	return signWith(t, f.key, map[string]any{"alg": "RS256", "typ": "JWT", "kid": f.kid}, f.claims(over))
}

func wantKind(t *testing.T, err error, k Kind) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Kind != k {
		t.Fatalf("error = %v, want kind %v", err, k)
	}
}

func TestValidToken(t *testing.T) {
	f := newFixture(t)
	c, err := f.v.Verify(f.token(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.String("repository") != "alice/x" || c.String("repository_owner_id") != "42" || c.JTI == "" {
		t.Fatalf("claims = %+v", c)
	}
	if c.Expires.Unix() != f.clk.now().Unix()+600 {
		t.Fatalf("expires = %v", c.Expires)
	}
}

func TestClaimStringOnlyReturnsJSONStrings(t *testing.T) {
	f := newFixture(t)
	c, err := f.v.Verify(f.token(t, map[string]any{"run_id": 123, "actor": "bob"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.String("run_id") != "" || c.String("actor") != "bob" || c.String("missing") != "" {
		t.Fatalf("run_id %q actor %q", c.String("run_id"), c.String("actor"))
	}
}

func TestAlgorithmMustBeRS256(t *testing.T) {
	f := newFixture(t)
	claims := f.claims(nil)
	cb, _ := json.Marshal(claims)
	body := b64(cb)
	mk := func(h map[string]any) string { hb, _ := json.Marshal(h); return b64(hb) + "." + body }

	// none, with an empty signature (and with a junk one).
	for _, alg := range []string{"none", "None", "NONE", ""} {
		for _, sig := range []string{"", b64([]byte("junk"))} {
			_, err := f.v.Verify(mk(map[string]any{"alg": alg, "kid": f.kid}) + "." + sig)
			wantKind(t, err, KindAlgorithm)
		}
	}
	// HS256 keyed with the public modulus (the classic confusion attack).
	hh := mk(map[string]any{"alg": "HS256", "kid": f.kid})
	mac := hmac.New(sha256.New, f.key.PublicKey.N.Bytes())
	mac.Write([]byte(hh))
	_, err := f.v.Verify(hh + "." + b64(mac.Sum(nil)))
	wantKind(t, err, KindAlgorithm)
	// ES256 and the other RS-family / PS-family algorithms.
	for _, alg := range []string{"ES256", "ES384", "HS384", "HS512", "RS384", "RS512", "PS256", "EdDSA", "rs256"} {
		_, err := f.v.Verify(mk(map[string]any{"alg": alg, "kid": f.kid}) + "." + b64(make([]byte, 256)))
		wantKind(t, err, KindAlgorithm)
	}
	// An alg that is not a string.
	_, err = f.v.Verify(mk(map[string]any{"alg": []string{"RS256"}, "kid": f.kid}) + "." + b64(make([]byte, 256)))
	wantKind(t, err, KindMalformed)
	// RS256 is accepted (control).
	if _, err := f.v.Verify(f.token(t, nil)); err != nil {
		t.Fatal(err)
	}
}

func TestKidRequired(t *testing.T) {
	f := newFixture(t)
	for _, h := range []map[string]any{{"alg": "RS256"}, {"alg": "RS256", "kid": ""}, {"alg": "RS256", "kid": 7}} {
		_, err := f.v.Verify(signWith(t, f.key, h, f.claims(nil)))
		wantKind(t, err, KindMalformed)
	}
}

func TestTamperedPayloadIsRejected(t *testing.T) {
	f := newFixture(t)
	parts := strings.Split(f.token(t, nil), ".")
	forged := f.claims(map[string]any{"repository_owner_id": "1", "repository_owner": "mallory"})
	fb, _ := json.Marshal(forged)
	_, err := f.v.Verify(parts[0] + "." + b64(fb) + "." + parts[2])
	wantKind(t, err, KindSignature)
}

func TestSignatureByAnotherKeyIsRejected(t *testing.T) {
	f := newFixture(t)
	other := genKey(t, 2048)
	tok := signWith(t, other, map[string]any{"alg": "RS256", "kid": f.kid}, f.claims(nil))
	_, err := f.v.Verify(tok)
	wantKind(t, err, KindSignature)
}

func TestTruncatedAndPaddedSignature(t *testing.T) {
	f := newFixture(t)
	tok := f.token(t, nil)
	i := strings.LastIndex(tok, ".")
	sig, _ := base64.RawURLEncoding.DecodeString(tok[i+1:])
	for name, bad := range map[string]string{
		"short":     b64(sig[:len(sig)-1]),
		"long":      b64(append(append([]byte{}, sig...), 0)),
		"zero":      b64(make([]byte, len(sig))),
		"std-b64":   base64.StdEncoding.EncodeToString(sig),
		"padded":    base64.URLEncoding.EncodeToString(sig) + "=",
		"not-b64":   "!!!!",
		"empty-sig": "",
	} {
		if _, err := f.v.Verify(tok[:i+1] + bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestUnknownKid(t *testing.T) {
	f := newFixture(t)
	tok := signWith(t, f.key, map[string]any{"alg": "RS256", "kid": "nope"}, f.claims(nil))
	_, err := f.v.Verify(tok)
	wantKind(t, err, KindUnknownKey)
}

func TestKeyShorterThan2048BitsIsRefused(t *testing.T) {
	small := genKey(t, 1024)
	f := newFixture(t)
	f.jwks.set(false, jwk("small", &small.PublicKey, nil), jwk(f.kid, &f.key.PublicKey, nil))
	tok := signWith(t, small, map[string]any{"alg": "RS256", "kid": "small"}, f.claims(nil))
	_, err := f.v.Verify(tok)
	wantKind(t, err, KindUnknownKey) // the weak key is never loaded
	if _, err := f.v.Verify(f.token(t, nil)); err != nil {
		t.Fatalf("the good key beside it must still work: %v", err)
	}
}

func TestJWKSKeyFiltering(t *testing.T) {
	f := newFixture(t)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other := genKey(t, 2048)
	enc := genKey(t, 2048)
	smallExp := genKey(t, 2048)
	f.jwks.set(false,
		map[string]any{"kty": "EC", "kid": "ec", "crv": "P-256", "use": "sig", "x": b64(ec.X.Bytes()), "y": b64(ec.Y.Bytes())},
		jwk("enc", &enc.PublicKey, map[string]any{"use": "enc"}),
		jwk("es-alg", &other.PublicKey, map[string]any{"alg": "ES256"}),
		jwk("nouse", &smallExp.PublicKey, map[string]any{"use": nil, "alg": nil}),
		jwk(f.kid, &f.key.PublicKey, nil),
	)
	for _, kid := range []string{"ec", "enc", "es-alg"} {
		_, err := f.v.Verify(signWith(t, other, map[string]any{"alg": "RS256", "kid": kid}, f.claims(nil)))
		wantKind(t, err, KindUnknownKey)
	}
	// "use" and "alg" absent is acceptable for an RSA key.
	if _, err := f.v.Verify(signWith(t, smallExp, map[string]any{"alg": "RS256", "kid": "nouse"}, f.claims(nil))); err != nil {
		t.Fatalf("key with no use/alg: %v", err)
	}
}

func TestOnlyNonRSAKeysMeansNoTrustedKey(t *testing.T) {
	f := newFixture(t)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	f.jwks.set(false, map[string]any{"kty": "EC", "kid": f.kid, "crv": "P-256", "x": b64(ec.X.Bytes()), "y": b64(ec.Y.Bytes())})
	_, err := f.v.Verify(f.token(t, nil))
	wantKind(t, err, KindUnknownKey)
}

func TestDuplicateKidIsAmbiguousAndRefused(t *testing.T) {
	f := newFixture(t)
	other := genKey(t, 2048)
	f.jwks.set(false, jwk(f.kid, &f.key.PublicKey, nil), jwk(f.kid, &other.PublicKey, nil))
	_, err := f.v.Verify(f.token(t, nil))
	wantKind(t, err, KindUnknownKey)
}

func TestIssuerMustMatchExactly(t *testing.T) {
	f := newFixture(t)
	for _, iss := range []string{"https://token.actions.githubusercontent.com/", "https://evil.example", "", "HTTPS://token.actions.githubusercontent.com", testIssuer + " "} {
		_, err := f.v.Verify(f.token(t, map[string]any{"iss": iss}))
		wantKind(t, err, KindIssuer)
	}
	_, err := f.v.Verify(f.token(t, map[string]any{"iss": nil}))
	wantKind(t, err, KindIssuer)
}

func TestAudience(t *testing.T) {
	f := newFixture(t)
	for name, aud := range map[string]any{
		"wrong":       "https://other.example",
		"prefix":      testAudience + "/x",
		"empty":       "",
		"two":         []string{testAudience, "https://other.example"},
		"two-same":    []string{testAudience, testAudience},
		"empty-array": []string{},
		"other-array": []string{"https://other.example"},
		"number":      7,
		"missing":     nil,
	} {
		_, err := f.v.Verify(f.token(t, map[string]any{"aud": aud}))
		if name == "number" || name == "missing" {
			if err == nil {
				t.Errorf("%s accepted", name)
			}
			continue
		}
		var e *Error
		if !errors.As(err, &e) || e.Kind != KindAudience {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Exactly one element equal to the audience is accepted.
	if _, err := f.v.Verify(f.token(t, map[string]any{"aud": []string{testAudience}})); err != nil {
		t.Fatalf("one-element array: %v", err)
	}
}

func TestTimeClaims(t *testing.T) {
	f := newFixture(t)
	now := f.clk.now().Unix()
	cases := []struct {
		name string
		over map[string]any
		want Kind // 0 = accepted
	}{
		{"expired", map[string]any{"exp": now - 600, "iat": now - 1200, "nbf": now - 1200}, KindExpired},
		{"expired beyond skew", map[string]any{"exp": now - 61}, KindExpired},
		{"expired within skew", map[string]any{"exp": now - 30, "iat": now - 600, "nbf": now - 600}, 0},
		{"nbf in the future", map[string]any{"nbf": now + 600}, KindNotYetValid},
		{"nbf beyond skew", map[string]any{"nbf": now + 61}, KindNotYetValid},
		{"nbf within skew", map[string]any{"nbf": now + 30}, 0},
		{"iat in the future", map[string]any{"iat": now + 600, "exp": now + 1200}, KindNotYetValid},
		{"iat within skew", map[string]any{"iat": now + 30}, 0},
		{"lifetime 61 min", map[string]any{"iat": now - 60, "nbf": now - 60, "exp": now - 60 + 3601}, KindLifetime},
		{"lifetime 1 h", map[string]any{"iat": now - 60, "nbf": now - 60, "exp": now - 60 + 3600}, 0},
		{"lifetime 1 day", map[string]any{"exp": now + 86400}, KindLifetime},
		{"exp before iat", map[string]any{"iat": now, "exp": now - 1}, KindLifetime},
		{"no exp", map[string]any{"exp": nil}, KindMalformed},
		{"no iat", map[string]any{"iat": nil}, KindMalformed},
		{"no nbf is fine", map[string]any{"nbf": nil}, 0},
		{"exp as string", map[string]any{"exp": fmt.Sprint(now + 600)}, KindMalformed},
		{"exp as float", map[string]any{"exp": float64(now) + 600.5}, 0},
	}
	for _, c := range cases {
		_, err := f.v.Verify(f.token(t, c.over))
		if c.want == 0 {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		var e *Error
		if !errors.As(err, &e) || e.Kind != c.want {
			t.Errorf("%s: got %v, want kind %v", c.name, err, c.want)
		}
	}
}

func TestJTIRequired(t *testing.T) {
	f := newFixture(t)
	for _, j := range []any{nil, "", 5, strings.Repeat("a", 300)} {
		_, err := f.v.Verify(f.token(t, map[string]any{"jti": j}))
		wantKind(t, err, KindClaims)
	}
}

func TestMalformedTokens(t *testing.T) {
	f := newFixture(t)
	good := f.token(t, nil)
	parts := strings.Split(good, ".")
	cases := map[string]string{
		"empty":            "",
		"no dots":          "abc",
		"two parts":        parts[0] + "." + parts[1],
		"four parts":       good + ".extra",
		"extra dots":       good + "...",
		"leading dot":      "." + good,
		"empty header":     "." + parts[1] + "." + parts[2],
		"empty payload":    parts[0] + ".." + parts[2],
		"bad b64 header":   "!!!." + parts[1] + "." + parts[2],
		"bad b64 payload":  parts[0] + ".@@@." + parts[2],
		"padded header":    parts[0] + "==." + parts[1] + "." + parts[2],
		"header not json":  b64([]byte("nope")) + "." + parts[1] + "." + parts[2],
		"header array":     b64([]byte(`["alg"]`)) + "." + parts[1] + "." + parts[2],
		"payload not json": parts[0] + "." + b64([]byte("nope")) + "." + parts[2],
		"whitespace":       " " + good,
		"newline":          good + "\n",
	}
	for name, tok := range cases {
		if _, err := f.v.Verify(tok); err == nil {
			t.Errorf("%s: accepted", name)
		} else {
			var e *Error
			if !errors.As(err, &e) {
				t.Errorf("%s: untyped error %v", name, err)
			}
		}
	}
}

func TestPayloadMustBeSignedBeforeItIsInterpreted(t *testing.T) {
	// A forged token with a wrong audience reports the signature failure, not
	// the audience: unsigned content is never judged.
	f := newFixture(t)
	other := genKey(t, 2048)
	tok := signWith(t, other, map[string]any{"alg": "RS256", "kid": f.kid}, f.claims(map[string]any{"aud": "x"}))
	_, err := f.v.Verify(tok)
	wantKind(t, err, KindSignature)
}

func TestJWKSDownFailsClosed(t *testing.T) {
	f := newFixture(t)
	f.jwks.set(true)
	_, err := f.v.Verify(f.token(t, nil))
	wantKind(t, err, KindKeysUnavailable)
	// Unreachable server.
	f.jwks.srv.Close()
	f2 := New(Config{Issuer: testIssuer, Audience: testAudience, JWKSURL: f.jwks.srv.URL, Now: f.clk.now})
	_, err = f2.Verify(f.token(t, nil))
	wantKind(t, err, KindKeysUnavailable)
}

func TestJWKSNon200AndGarbageFailClosed(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"404":      func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) },
		"garbage":  func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>")) },
		"redirect": func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://127.0.0.1:1/", 302) },
	} {
		srv := httptest.NewServer(h)
		f := newFixture(t)
		v := New(Config{Issuer: testIssuer, Audience: testAudience, JWKSURL: srv.URL, Now: f.clk.now})
		_, err := v.Verify(f.token(t, nil))
		var e *Error
		if !errors.As(err, &e) || e.Kind != KindKeysUnavailable {
			t.Errorf("%s: %v", name, err)
		}
		srv.Close()
	}
}

func TestJWKSResponseSizeIsCapped(t *testing.T) {
	f := newFixture(t)
	f.jwks.extra = maxJWKSBytes + 10
	_, err := f.v.Verify(f.token(t, nil))
	wantKind(t, err, KindKeysUnavailable)
}

func TestJWKSFetchTimesOut(t *testing.T) {
	f := newFixture(t)
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-block }))
	defer srv.Close()
	defer close(block)
	v := New(Config{Issuer: testIssuer, Audience: testAudience, JWKSURL: srv.URL, Now: f.clk.now, FetchTimeout: 150 * time.Millisecond})
	start := time.Now()
	_, err := v.Verify(f.token(t, nil))
	wantKind(t, err, KindKeysUnavailable)
	if time.Since(start) > 3*time.Second {
		t.Fatal("did not time out")
	}
}

func TestKnownKidIsServedFromCache(t *testing.T) {
	f := newFixture(t)
	for i := 0; i < 5; i++ {
		if _, err := f.v.Verify(f.token(t, nil)); err != nil {
			t.Fatal(err)
		}
	}
	if n := f.jwks.hits.Load(); n != 1 {
		t.Fatalf("%d fetches, want 1", n)
	}
}

func TestUnknownKidsCannotHammerTheIssuer(t *testing.T) {
	f := newFixture(t)
	if _, err := f.v.Verify(f.token(t, nil)); err != nil { // primes the cache
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		tok := signWith(t, f.key, map[string]any{"alg": "RS256", "kid": fmt.Sprintf("garbage-%d", i)}, f.claims(nil))
		_, err := f.v.Verify(tok)
		wantKind(t, err, KindUnknownKey)
	}
	if n := f.jwks.hits.Load(); n != 1 {
		t.Fatalf("%d fetches after 50 garbage kids within a minute, want 1", n)
	}
	// After a minute one unknown kid may trigger exactly one refetch.
	f.clk.add(61 * time.Second)
	for i := 0; i < 5; i++ {
		tok := signWith(t, f.key, map[string]any{"alg": "RS256", "kid": fmt.Sprintf("garbage-late-%d", i)}, f.claims(nil))
		wantKind(t, func() error { _, err := f.v.Verify(tok); return err }(), KindUnknownKey)
	}
	if n := f.jwks.hits.Load(); n != 2 {
		t.Fatalf("%d fetches, want 2", n)
	}
}

func TestKeyRotationIsPickedUpAfterTheMinute(t *testing.T) {
	f := newFixture(t)
	if _, err := f.v.Verify(f.token(t, nil)); err != nil {
		t.Fatal(err)
	}
	newKey := genKey(t, 2048)
	f.jwks.set(false, jwk(f.kid, &f.key.PublicKey, nil), jwk("kid-2", &newKey.PublicKey, nil))
	tok := signWith(t, newKey, map[string]any{"alg": "RS256", "kid": "kid-2"}, f.claims(nil))
	_, err := f.v.Verify(tok) // within the minute: not refetched
	wantKind(t, err, KindUnknownKey)
	f.clk.add(61 * time.Second)
	if _, err := f.v.Verify(tok); err != nil {
		t.Fatalf("after the minute: %v", err)
	}
}

func TestFailedFetchesAreAlsoRateLimited(t *testing.T) {
	f := newFixture(t)
	f.jwks.set(true)
	for i := 0; i < 20; i++ {
		_, err := f.v.Verify(f.token(t, nil))
		wantKind(t, err, KindKeysUnavailable)
	}
	if n := f.jwks.hits.Load(); n != 1 {
		t.Fatalf("%d fetches while the issuer is down, want 1 per minute", n)
	}
	f.jwks.set(false)
	f.clk.add(61 * time.Second)
	if _, err := f.v.Verify(f.token(t, nil)); err != nil {
		t.Fatalf("recovery: %v", err)
	}
}

func TestStaleKeysAreUsedBrieflyAndNeverBeyond24Hours(t *testing.T) {
	f := newFixture(t)
	if _, err := f.v.Verify(f.token(t, nil)); err != nil {
		t.Fatal(err)
	}
	f.jwks.set(true)
	// Past the refresh interval, the issuer down: the cached key still works.
	f.clk.add(3 * time.Hour)
	if _, err := f.v.Verify(f.token(t, nil)); err != nil {
		t.Fatalf("3h-old keys with the issuer down: %v", err)
	}
	// Older than 24h since the last successful fetch: refuse.
	f.clk.add(22 * time.Hour)
	_, err := f.v.Verify(f.token(t, nil))
	wantKind(t, err, KindKeysUnavailable)
	// And it recovers once the issuer does.
	f.jwks.set(false)
	f.clk.add(2 * time.Minute)
	if _, err := f.v.Verify(f.token(t, nil)); err != nil {
		t.Fatalf("recovery: %v", err)
	}
}

func TestPeekRepositoryIsTruncatedAndSanitised(t *testing.T) {
	f := newFixture(t)
	if got := PeekRepository(f.token(t, nil)); got != "alice/x" {
		t.Fatalf("%q", got)
	}
	evil := "a/b\n\x1b[31m" + strings.Repeat("z", 200)
	got := PeekRepository(f.token(t, map[string]any{"repository": evil}))
	if len(got) > 70 || strings.ContainsAny(got, "\n\x1b\r") {
		t.Fatalf("%q", got)
	}
	for _, bad := range []string{"", "x", "a.b.c", "a." + b64([]byte("nope")) + ".c", "a." + b64([]byte(`{"repository":5}`)) + ".c"} {
		if got := PeekRepository(bad); got != "" {
			t.Errorf("%q -> %q", bad, got)
		}
	}
}

func TestReplayCache(t *testing.T) {
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	rc := NewReplayCache(3, clk.now)
	exp := clk.now().Add(10 * time.Minute)
	if err := rc.Remember("a", exp); err != nil {
		t.Fatal(err)
	}
	if err := rc.Remember("a", exp); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
	rc.Remember("b", exp)
	rc.Remember("c", exp)
	// At the cap: refuse rather than forget.
	if err := rc.Remember("d", exp); !errors.Is(err, ErrReplayCacheFull) {
		t.Fatalf("full: %v", err)
	}
	if err := rc.Remember("a", exp); !errors.Is(err, ErrReplay) {
		t.Fatalf("a was forgotten: %v", err)
	}
	// Entries are kept until exp plus the clock skew, then pruned.
	clk.add(10*time.Minute + skew - time.Second)
	if err := rc.Remember("a", exp.Add(time.Hour)); !errors.Is(err, ErrReplay) {
		t.Fatalf("forgotten before exp+skew: %v", err)
	}
	clk.add(2 * time.Second)
	if err := rc.Remember("d", clk.now().Add(time.Minute)); err != nil {
		t.Fatalf("expired entries must make room: %v", err)
	}
	if rc.Len() != 1 {
		t.Fatalf("len = %d, want 1", rc.Len())
	}
}

func TestReplayCacheConcurrentSameJTIAcceptedOnce(t *testing.T) {
	rc := NewReplayCache(100, time.Now)
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rc.Remember("same", time.Now().Add(time.Minute)) == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d acceptances", ok.Load())
	}
}

func TestParseIssuerAndJWKSURL(t *testing.T) {
	if u, err := JWKSURLFor("https://token.actions.githubusercontent.com"); err != nil || u != "https://token.actions.githubusercontent.com/.well-known/jwks" {
		t.Fatalf("%q %v", u, err)
	}
	if u, err := JWKSURLFor("https://ghe.example/_services/token/"); err != nil || u != "https://ghe.example/_services/token/.well-known/jwks" {
		t.Fatalf("%q %v", u, err)
	}
	for _, bad := range []string{"not a url", "ftp://x", "https://", "https://u:p@host/", "https://host/?q=1", "https://host/#f", "/relative"} {
		if _, err := JWKSURLFor(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
