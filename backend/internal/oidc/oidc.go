// Package oidc verifies OIDC ID tokens (JWS compact serialisation, RS256) the
// way the registry needs for GitHub Actions: a small verifier on the standard
// library instead of a JWT dependency, so the accepted surface is exactly what
// is written here.
//
// What it refuses, by construction: any alg other than RS256 (the header is
// checked, never used to choose behaviour), a missing kid, keys that are not
// RSA or are shorter than 2048 bits, signatures of the wrong length, any
// segment that is not strict unpadded base64url, anything but exactly three
// segments, and claims that are not signed (claims are read only after the
// signature verifies). The JWKS location is configured by the operator; it is
// never taken from the token or from a discovery document.
package oidc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Kind classifies a verification failure. The HTTP layer maps kinds to broad
// reasons ("signature", "audience", ...); Detail never carries token content.
type Kind int

const (
	KindMalformed       Kind = iota + 1 // not a well-formed three-part RS256 JWS
	KindAlgorithm                       // alg is not RS256
	KindUnknownKey                      // kid is not in the issuer's key set
	KindSignature                       // signature does not verify
	KindIssuer                          // iss is not the configured issuer
	KindAudience                        // aud is not the configured audience
	KindExpired                         // exp is in the past
	KindNotYetValid                     // nbf or iat is in the future
	KindLifetime                        // exp - iat is not within (0, 1h]
	KindClaims                          // a required claim is missing or invalid
	KindKeysUnavailable                 // the key set could not be obtained (fail closed)
)

func (k Kind) String() string {
	return [...]string{"", "malformed", "algorithm", "unknown key", "signature", "issuer", "audience", "expired", "not yet valid", "lifetime", "claims", "keys unavailable"}[k]
}

// Error is a verification failure.
type Error struct {
	Kind   Kind
	Detail string
}

func (e *Error) Error() string {
	if e.Detail == "" {
		return e.Kind.String()
	}
	return e.Kind.String() + ": " + e.Detail
}

func fail(k Kind, format string, a ...any) *Error {
	return &Error{Kind: k, Detail: fmt.Sprintf(format, a...)}
}

const (
	skew        = 60 * time.Second // allowed clock skew on exp, nbf and iat
	maxLifetime = time.Hour        // exp - iat
	minRSABits  = 2048
	maxKidLen   = 128
	maxJTILen   = 256

	minRefetch   = time.Minute     // at most one JWKS fetch attempt per minute
	keyTTL       = time.Hour       // a known kid is re-checked against the issuer after this
	maxStale     = 24 * time.Hour  // cached keys are never used when older than this
	maxJWKSBytes = 256 << 10       // response size cap
	maxJWKSKeys  = 64              // keys read from one response
	fetchTimeout = 5 * time.Second // default JWKS fetch timeout
)

// Config configures a Verifier.
type Config struct {
	Issuer   string // exact iss value
	Audience string // exact aud value
	JWKSURL  string // where the issuer's keys are fetched from
	// Now is the clock; nil means time.Now. FetchTimeout is the JWKS request
	// timeout; zero means 5s.
	Now          func() time.Time
	FetchTimeout time.Duration
}

// Verifier verifies ID tokens against one issuer's JWKS, which it caches.
type Verifier struct {
	cfg Config
	hc  *http.Client

	mu          sync.Mutex // guards the fields below, and serialises fetches
	keys        map[string]*rsa.PublicKey
	fetchedAt   time.Time // last successful fetch
	lastAttempt time.Time // last fetch attempt, successful or not
	lastOK      bool      // whether that attempt succeeded
}

// New returns a Verifier. Redirects are never followed when fetching keys.
func New(cfg Config) *Verifier {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.FetchTimeout <= 0 {
		cfg.FetchTimeout = fetchTimeout
	}
	return &Verifier{cfg: cfg, hc: &http.Client{
		Timeout:       cfg.FetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

// Claims are the verified claims of a token.
type Claims struct {
	JTI     string
	Expires time.Time
	raw     map[string]json.RawMessage
}

// String returns claim k when it is a JSON string, and "" otherwise (absent,
// number, object, ...). GitHub sends its identifiers as strings.
func (c *Claims) String(k string) string {
	var s string
	if json.Unmarshal(c.raw[k], &s) != nil {
		return ""
	}
	return s
}

// segment decodes one strict base64url segment: unpadded, URL alphabet, and
// nothing else (Go's decoder would silently skip CR and LF).
func segment(s string) ([]byte, bool) {
	if s == "" {
		return nil, false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return nil, false
		}
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return b, err == nil
}

// Verify checks raw and returns its claims. Checks run in this order: shape,
// alg, kid, signature, then the claims, so nothing unsigned is interpreted.
func (v *Verifier) Verify(raw string) (*Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fail(KindMalformed, "expected 3 segments")
	}
	hb, ok1 := segment(parts[0])
	pb, ok2 := segment(parts[1])
	sig, ok3 := segment(parts[2])
	if !ok1 || !ok2 {
		return nil, fail(KindMalformed, "bad base64url segment")
	}
	var hdr map[string]json.RawMessage
	if json.Unmarshal(hb, &hdr) != nil || hdr == nil {
		return nil, fail(KindMalformed, "header is not a JSON object")
	}
	var alg string
	if json.Unmarshal(hdr["alg"], &alg) != nil {
		return nil, fail(KindMalformed, "alg is not a string")
	}
	if alg != "RS256" { // exact, case-sensitive: "none", "HS256", "rs256" all stop here
		return nil, fail(KindAlgorithm, "only RS256 is accepted")
	}
	var kid string
	if json.Unmarshal(hdr["kid"], &kid) != nil || kid == "" || len(kid) > maxKidLen {
		return nil, fail(KindMalformed, "kid is required")
	}
	if !ok3 {
		return nil, fail(KindMalformed, "bad signature segment")
	}

	pub, err := v.key(kid)
	if err != nil {
		return nil, err
	}
	if len(sig) != (pub.N.BitLen()+7)/8 {
		return nil, fail(KindSignature, "signature has the wrong length")
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) != nil {
		return nil, fail(KindSignature, "signature does not verify")
	}

	var cl map[string]json.RawMessage
	if json.Unmarshal(pb, &cl) != nil || cl == nil {
		return nil, fail(KindMalformed, "payload is not a JSON object")
	}
	return v.checkClaims(cl)
}

func numeric(raw json.RawMessage) (time.Time, bool) {
	var f float64
	if json.Unmarshal(raw, &f) != nil || math.IsNaN(f) || math.IsInf(f, 0) || f < 0 || f > 1e12 {
		return time.Time{}, false
	}
	sec := math.Floor(f)
	return time.Unix(int64(sec), int64((f-sec)*1e9)), true
}

func (v *Verifier) checkClaims(cl map[string]json.RawMessage) (*Claims, error) {
	str := func(k string) (string, bool) {
		var s string
		return s, json.Unmarshal(cl[k], &s) == nil
	}
	if iss, ok := str("iss"); !ok || iss != v.cfg.Issuer {
		return nil, fail(KindIssuer, "iss is not the configured issuer")
	}
	// aud: exactly the configured string, or an array of exactly that one.
	var aud string
	var auds []string
	switch {
	case json.Unmarshal(cl["aud"], &aud) == nil:
		auds = []string{aud}
	case json.Unmarshal(cl["aud"], &auds) != nil:
		return nil, fail(KindAudience, "aud is not a string or array of strings")
	}
	if len(auds) != 1 || auds[0] != v.cfg.Audience {
		return nil, fail(KindAudience, "aud is not the configured audience")
	}

	exp, ok := numeric(cl["exp"])
	if !ok {
		return nil, fail(KindMalformed, "exp is required")
	}
	iat, ok := numeric(cl["iat"])
	if !ok {
		return nil, fail(KindMalformed, "iat is required")
	}
	now := v.cfg.Now()
	if !now.Before(exp.Add(skew)) {
		return nil, fail(KindExpired, "token has expired")
	}
	if raw, present := cl["nbf"]; present {
		nbf, ok := numeric(raw)
		if !ok {
			return nil, fail(KindMalformed, "nbf is invalid")
		}
		if nbf.After(now.Add(skew)) {
			return nil, fail(KindNotYetValid, "nbf is in the future")
		}
	}
	if iat.After(now.Add(skew)) {
		return nil, fail(KindNotYetValid, "iat is in the future")
	}
	if life := exp.Sub(iat); life <= 0 || life > maxLifetime {
		return nil, fail(KindLifetime, "token lifetime must be positive and at most 1h")
	}
	jti, ok := str("jti")
	if !ok || jti == "" || len(jti) > maxJTILen {
		return nil, fail(KindClaims, "jti is required")
	}
	return &Claims{JTI: jti, Expires: exp, raw: cl}, nil
}

// key returns the RSA key for kid, fetching the JWKS when the rules allow.
//
// Rules: a kid cached less than keyTTL ago is served without a request. Any
// other need (unknown kid, or a known one older than keyTTL) triggers a fetch
// only if the previous attempt, successful or not, is at least a minute old,
// so garbage kids and an outage both cost at most one request a minute. If the
// fetch fails or is not allowed, a cached key is still served while the last
// successful fetch is under 24h old; beyond that nothing is served from the
// cache. An unknown kid after a successful, current fetch is KindUnknownKey;
// when keys could not be obtained it is KindKeysUnavailable.
func (v *Verifier) key(kid string) (*rsa.PublicKey, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.cfg.Now()
	age := now.Sub(v.fetchedAt)
	have := !v.fetchedAt.IsZero() && age >= 0 && age < maxStale
	if k, ok := v.keys[kid]; ok && have && age < keyTTL {
		return k, nil
	}
	if v.lastAttempt.IsZero() || now.Sub(v.lastAttempt) >= minRefetch || now.Before(v.lastAttempt) {
		v.lastAttempt = now
		keys, err := v.fetch()
		if err != nil {
			log.Printf("oidc: fetching JWKS: %v", err)
			v.lastOK = false
		} else {
			v.keys, v.fetchedAt, v.lastOK = keys, now, true
			age, have = 0, true
		}
	}
	if k, ok := v.keys[kid]; ok && have {
		return k, nil
	}
	if have && v.lastOK {
		return nil, fail(KindUnknownKey, "kid is not in the issuer's key set")
	}
	return nil, fail(KindKeysUnavailable, "the issuer's keys could not be fetched")
}

type jwkDoc struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

func (v *Verifier) fetch() (map[string]*rsa.PublicKey, error) {
	req, err := http.NewRequest("GET", v.cfg.JWKSURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxJWKSBytes {
		return nil, errors.New("response too large")
	}
	var doc jwkDoc
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("decoding: %w", err)
	}
	keys := map[string]*rsa.PublicKey{}
	dup := map[string]bool{}
	for i, k := range doc.Keys {
		if i >= maxJWKSKeys {
			break
		}
		if k.Kid == "" || len(k.Kid) > maxKidLen || k.Kty != "RSA" || (k.Use != "" && k.Use != "sig") || (k.Alg != "" && k.Alg != "RS256") {
			continue
		}
		if _, seen := keys[k.Kid]; seen || dup[k.Kid] {
			// Two keys claiming one kid is ambiguous: trust neither.
			delete(keys, k.Kid)
			dup[k.Kid] = true
			continue
		}
		pub, ok := rsaKey(k.N, k.E)
		if !ok {
			dup[k.Kid] = true // an unusable key still owns its kid
			continue
		}
		keys[k.Kid] = pub
	}
	return keys, nil
}

func rsaKey(nB64, eB64 string) (*rsa.PublicKey, bool) {
	nb, ok1 := segment(nB64)
	eb, ok2 := segment(eB64)
	if !ok1 || !ok2 || len(eb) > 4 {
		return nil, false
	}
	n := new(big.Int).SetBytes(nb)
	e := new(big.Int).SetBytes(eb)
	if n.BitLen() < minRSABits || n.BitLen() > 16384 || !e.IsInt64() || e.Int64() < 3 || e.Int64()%2 == 0 || e.Int64() > math.MaxInt32 {
		return nil, false
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, true
}

// PeekRepository returns the UNVERIFIED repository claim of raw, truncated to
// 64 characters with anything unprintable removed, for log lines about
// rejected tokens. It never errors and proves nothing.
func PeekRepository(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return ""
	}
	pb, ok := segment(parts[1])
	if !ok {
		return ""
	}
	var cl struct {
		Repository string `json:"repository"`
	}
	if json.Unmarshal(pb, &cl) != nil {
		return ""
	}
	var out []rune
	for _, r := range cl.Repository {
		if !unicode.IsPrint(r) {
			continue
		}
		if len(out) == 64 {
			break
		}
		out = append(out, r)
	}
	return string(out)
}

// ValidateEndpoint checks an operator-supplied http(s) URL: absolute, a host,
// no credentials, query or fragment. http is accepted only for a loopback
// host (tests and local development), never for a real issuer.
func ValidateEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("must be an absolute https:// URL without credentials, query or fragment")
	}
	switch u.Scheme {
	case "https":
	case "http":
		if h := u.Hostname(); h != "localhost" && !(net.ParseIP(h) != nil && net.ParseIP(h).IsLoopback()) {
			return nil, errors.New("http:// is only allowed for localhost; use https://")
		}
	default:
		return nil, errors.New("must be an absolute https:// URL")
	}
	return u, nil
}

// JWKSURLFor derives the default JWKS URL from an issuer: <issuer>/.well-known/jwks.
func JWKSURLFor(issuer string) (string, error) {
	u, err := ValidateEndpoint(issuer)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(u.String(), "/") + "/.well-known/jwks", nil
}

// ErrReplay is returned by ReplayCache.Remember for a jti seen before;
// ErrReplayCacheFull when no more can be remembered.
var (
	ErrReplay          = errors.New("token id already used")
	ErrReplayCacheFull = errors.New("replay cache is full")
)

// ReplayCache remembers accepted jti values until their token can no longer
// verify (exp plus the allowed skew). It has a hard cap: when full of live
// entries it refuses new ones rather than forgetting, so a remembered token
// can never be replayed because the cache was crowded.
type ReplayCache struct {
	mu   sync.Mutex
	max  int
	now  func() time.Time
	seen map[string]time.Time
}

func NewReplayCache(max int, now func() time.Time) *ReplayCache {
	if now == nil {
		now = time.Now
	}
	return &ReplayCache{max: max, now: now, seen: map[string]time.Time{}}
}

// Remember records jti until exp+skew. It is atomic: of concurrent calls with
// the same jti exactly one returns nil.
func (r *ReplayCache) Remember(jti string, exp time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	if until, ok := r.seen[jti]; ok && now.Before(until) {
		return ErrReplay
	}
	if len(r.seen) >= r.max {
		for k, until := range r.seen {
			if !now.Before(until) {
				delete(r.seen, k)
			}
		}
		if len(r.seen) >= r.max {
			return ErrReplayCacheFull
		}
	}
	r.seen[jti] = exp.Add(skew)
	return nil
}

// Len is the number of remembered entries (including expired ones not yet pruned).
func (r *ReplayCache) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.seen)
}
