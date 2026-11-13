package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/MasonD-007/capm/backend/internal/oidc"
)

// OIDCConfig enables POST /v1/auth/oidc. A nil *OIDCConfig in Config disables
// the endpoint (it answers 404).
type OIDCConfig struct {
	Issuer   string // exact iss; GitHub Actions: https://token.actions.githubusercontent.com
	JWKSURL  string // where the issuer's keys are served
	Audience string // exact aud the workflow must request
}

const (
	// ciTokenLifetime is fixed: it does not follow TOKEN_TTL_DAYS, and the
	// token is never renewable.
	ciTokenLifetime = 15 * time.Minute
	// maxActiveCITokens caps live CI tokens per account, so valid GitHub
	// tokens (anyone can mint one for any audience) cannot grow the tokens
	// table or the replay cache without bound.
	maxActiveCITokens = 20
	maxOIDCBody       = 16 << 10
	replayCacheCap    = 10000
	ownerCacheTTL     = 2 * time.Minute
	ownerCacheMax     = 1024
	ownerLookupWait   = 5 * time.Second
	retryAfterSeconds = "60"
)

// oidcState is the endpoint's runtime state.
type oidcState struct {
	cfg      OIDCConfig
	verifier *oidc.Verifier
	replay   *oidc.ReplayCache
	lookupHC *http.Client

	mu     sync.Mutex
	owners map[int64]ownerInfo
}

type ownerInfo struct {
	login, typ string
	at         time.Time
}

func newOIDCState(c *OIDCConfig) *oidcState {
	return &oidcState{
		cfg:      *c,
		verifier: oidc.New(oidc.Config{Issuer: c.Issuer, Audience: c.Audience, JWKSURL: c.JWKSURL}),
		replay:   oidc.NewReplayCache(replayCacheCap, nil),
		lookupHC: &http.Client{Timeout: ownerLookupWait},
		owners:   map[int64]ownerInfo{},
	}
}

var (
	digitsRe = regexp.MustCompile(`^[1-9][0-9]{0,17}$`)
	loginRe  = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	// recordedClaims are the claims stored with a CI token (and so with the
	// versions it publishes): the subset the registry may show or audit.
	recordedClaims = []string{"repository", "repository_id", "repository_owner_id", "workflow_ref",
		"job_workflow_ref", "ref", "sha", "run_id", "event_name", "actor", "actor_id"}
)

// oidcRefuse writes the response and the one log line for a failed exchange.
// reason is a broad category; the log line carries the unverified repository
// claim (truncated and sanitised by oidc.PeekRepository), never the token.
func (s *Service) oidcRefuse(w http.ResponseWriter, rawToken string, code int, reason, msg string) {
	log.Printf("auth: oidc exchange refused: reason=%q status=%d repository=%q", reason, code, oidc.PeekRepository(rawToken))
	if code == http.StatusServiceUnavailable {
		w.Header().Set("Retry-After", retryAfterSeconds)
	}
	writeErr(w, code, msg)
}

// verifyErr maps a verifier failure to a status and a message that names the
// broad check that failed and nothing from the token.
func verifyErr(err error) (code int, reason, msg string) {
	var e *oidc.Error
	if !errors.As(err, &e) {
		return http.StatusUnauthorized, "invalid", "token rejected"
	}
	switch e.Kind {
	case oidc.KindKeysUnavailable:
		return http.StatusServiceUnavailable, "keys unavailable", "could not fetch the token issuer's signing keys; retry shortly"
	case oidc.KindIssuer:
		return http.StatusUnauthorized, "issuer", "token rejected: wrong issuer"
	case oidc.KindAudience:
		return http.StatusUnauthorized, "audience", "token rejected: wrong audience"
	case oidc.KindExpired:
		return http.StatusUnauthorized, "expired", "token rejected: expired"
	case oidc.KindNotYetValid:
		return http.StatusUnauthorized, "not yet valid", "token rejected: not yet valid"
	case oidc.KindLifetime:
		return http.StatusUnauthorized, "lifetime", "token rejected: lifetime too long"
	case oidc.KindClaims:
		return http.StatusUnauthorized, "claims", "token rejected: a required claim is missing or invalid"
	default: // malformed, algorithm, unknown key, signature
		return http.StatusUnauthorized, e.Kind.String(), "token rejected: signature or format is invalid"
	}
}

// cleanClaim makes a claim value safe to store and print: valid UTF-8, no
// control characters, at most max characters.
func cleanClaim(v string, max int) string {
	v = cleanTokenName(v)
	if r := []rune(v); len(r) > max {
		v = string(r[:max])
	}
	return v
}

// oidcExchange trades a GitHub Actions OIDC token for a short-lived, publish-
// only registry token for the repository owner's account.
func (s *Service) oidcExchange(w http.ResponseWriter, r *http.Request) {
	o := s.oidc
	if o == nil {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	var in struct {
		Token string `json:"token"`
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxOIDCBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeErr(w, http.StatusRequestEntityTooLarge, "request too large")
		} else {
			writeErr(w, http.StatusBadRequest, "could not read the request")
		}
		return
	}
	if json.Unmarshal(b, &in) != nil || in.Token == "" {
		writeErr(w, http.StatusBadRequest, `body must be JSON like {"token": "<OIDC ID token>"}`)
		return
	}
	raw := in.Token

	claims, err := o.verifier.Verify(raw)
	if err != nil {
		code, reason, msg := verifyErr(err)
		s.oidcRefuse(w, raw, code, reason, msg)
		return
	}

	// Identity and event claims. These are signed, but still checked for
	// shape: everything below is stored or compared.
	ownerIDStr, owner, repo, event := claims.String("repository_owner_id"), claims.String("repository_owner"),
		claims.String("repository"), claims.String("event_name")
	ownerRepo, _, hasSlash := strings.Cut(repo, "/")
	if !digitsRe.MatchString(ownerIDStr) || !loginRe.MatchString(owner) || !hasSlash || len(repo) > 140 ||
		!strings.EqualFold(ownerRepo, owner) || event == "" {
		s.oidcRefuse(w, raw, http.StatusUnauthorized, "claims", "token rejected: a required claim is missing or invalid")
		return
	}
	// A pull request (including one from a fork) must not publish. For
	// pull_request_target the ref and sub look exactly like a push to the base
	// branch, so event_name is the only reliable signal; refuse every
	// pull_request* event.
	if strings.HasPrefix(event, "pull_request") {
		s.oidcRefuse(w, raw, http.StatusForbidden, "pull request event", "pull request workflows may not publish")
		return
	}
	ownerID, _ := strconv.ParseInt(ownerIDStr, 10, 64)

	// GitHub's claim set says who owns the repository but not whether that
	// owner is a user or an organisation, so ask GitHub (no trust in the
	// token for this) and fail closed.
	info, err := s.ownerInfo(ownerID)
	if err != nil {
		log.Printf("auth: oidc owner lookup: %v", err)
		s.oidcRefuse(w, raw, http.StatusServiceUnavailable, "owner lookup failed", "could not verify the repository owner with GitHub; retry shortly")
		return
	}
	switch info.typ {
	case "User":
	case "Organization":
		s.oidcRefuse(w, raw, http.StatusForbidden, "owner is an organisation", "organisation namespaces are not supported yet")
		return
	default:
		s.oidcRefuse(w, raw, http.StatusForbidden, "owner is not a user", "the repository owner is not a user account")
		return
	}

	banned, err := s.store.IsBanned(ownerID)
	if err != nil {
		log.Printf("auth: ban lookup: %v", err)
		s.oidcRefuse(w, raw, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	if banned {
		s.oidcRefuse(w, raw, http.StatusForbidden, "banned", "this account is banned from the registry")
		return
	}
	if n, err := s.store.CountLiveTokens(ownerID, ScopePublish); err != nil {
		log.Printf("auth: count ci tokens: %v", err)
		s.oidcRefuse(w, raw, http.StatusInternalServerError, "internal", "internal error")
		return
	} else if n >= maxActiveCITokens {
		s.oidcRefuse(w, raw, http.StatusTooManyRequests, "too many active CI tokens", "too many active CI tokens for this account; they expire after 15 minutes, or revoke some with capm tokens")
		return
	}

	// Everything that can refuse has run: only now is the token id spent, so a
	// refusal above (or a retry after a GitHub outage) does not burn it.
	switch err := o.replay.Remember(claims.JTI, claims.Expires); {
	case errors.Is(err, oidc.ErrReplay):
		s.oidcRefuse(w, raw, http.StatusUnauthorized, "replay", "token rejected: already used (replay)")
		return
	case err != nil:
		log.Printf("auth: oidc replay cache is full (%d entries); refusing new exchanges", replayCacheCap)
		s.oidcRefuse(w, raw, http.StatusServiceUnavailable, "replay cache full", "too many recent exchanges; retry shortly")
		return
	}

	// Same as device login: the account's current login, renames included.
	if err := s.store.UpsertUser(ownerID, info.login); err != nil {
		log.Printf("auth: upsert user: %v", err)
		s.oidcRefuse(w, raw, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	rec := map[string]string{}
	for _, k := range recordedClaims {
		if v := cleanClaim(claims.String(k), 300); v != "" {
			rec[k] = v
		}
	}
	cj, err := json.Marshal(rec)
	if err != nil {
		s.oidcRefuse(w, raw, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		log.Printf("auth: rand: %v", err)
		s.oidcRefuse(w, raw, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	tok := base64.RawURLEncoding.EncodeToString(buf)
	exp := time.Now().Add(ciTokenLifetime)
	if err := s.store.CreateScopedToken(hashToken(tok), ownerID, cleanTokenName("ci:"+rec["repository"]), exp, ScopePublish, string(cj)); err != nil {
		log.Printf("auth: store ci token: %v", err)
		s.oidcRefuse(w, raw, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	log.Printf("auth: oidc exchange ok: repository=%q owner_id=%d jti_expires=%s", cleanClaim(rec["repository"], 64), ownerID, claims.Expires.UTC().Format(time.RFC3339))
	writeJSON(w, 200, map[string]string{"token": tok, "expiresAt": exp.UTC().Format(time.RFC3339), "login": info.login})
}

// ownerInfo resolves a GitHub account id to its current login and type
// ("User" or "Organization") with GET /user/<id> on the GitHub API the
// service already talks to, caching successes for ownerCacheTTL. Failures are
// never cached.
func (s *Service) ownerInfo(id int64) (ownerInfo, error) {
	o := s.oidc
	o.mu.Lock()
	if c, ok := o.owners[id]; ok && time.Since(c.at) < ownerCacheTTL {
		o.mu.Unlock()
		return c, nil
	}
	o.mu.Unlock()

	req, err := http.NewRequest("GET", s.cfg.APIURL+"/user/"+strconv.FormatInt(id, 10), nil)
	if err != nil {
		return ownerInfo{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := o.lookupHC.Do(req)
	if err != nil {
		return ownerInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ownerInfo{}, fmt.Errorf("github /user/%d returned status %s", id, resp.Status)
	}
	var u struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Type  string `json:"type"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&u); err != nil {
		return ownerInfo{}, err
	}
	if u.ID != id || !loginRe.MatchString(u.Login) || u.Type == "" || !utf8.ValidString(u.Type) {
		return ownerInfo{}, errors.New("github returned an unexpected identity")
	}
	info := ownerInfo{login: u.Login, typ: u.Type, at: time.Now()}
	o.mu.Lock()
	if len(o.owners) >= ownerCacheMax {
		o.owners = map[int64]ownerInfo{}
	}
	o.owners[id] = info
	o.mu.Unlock()
	return info, nil
}

// ScopePublish is the scope of CI tokens; the API package enforces it.
const ScopePublish = "publish"
