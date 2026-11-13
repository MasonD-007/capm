// Package auth implements GitHub device-flow login and capm API tokens.
//
// The backend proxies GitHub's device flow. Only the device_code is accepted
// from the client; the user's identity always comes from GitHub's /user
// endpoint. GitHub's access token is used once and discarded; the capm token
// is returned once and only its sha256 hash is stored.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/MasonD-007/capm/backend/internal/store"
)

type Config struct {
	ClientID string // required for the auth routes to work
	APIURL   string // default https://api.github.com
	OAuthURL string // default https://github.com
	// AdminIDs are the GitHub numeric ids allowed to use /v1/admin/ (see
	// ParseAdminIDs). Empty means there are no admins.
	AdminIDs []int64
	// TokenTTL is how long newly issued tokens stay valid; 0 means forever.
	TokenTTL time.Duration
	// OIDC enables POST /v1/auth/oidc (publish from CI); nil disables it.
	OIDC *OIDCConfig
}

type Service struct {
	store *store.Store
	cfg   Config
	hc    *http.Client
	admin map[int64]bool
	oidc  *oidcState // nil = endpoint disabled
}

func New(st *store.Store, cfg Config) *Service {
	if cfg.APIURL == "" {
		cfg.APIURL = "https://api.github.com"
	}
	if cfg.OAuthURL == "" {
		cfg.OAuthURL = "https://github.com"
	}
	cfg.APIURL = strings.TrimRight(cfg.APIURL, "/")
	cfg.OAuthURL = strings.TrimRight(cfg.OAuthURL, "/")
	admin := map[int64]bool{}
	for _, id := range cfg.AdminIDs {
		admin[id] = true
	}
	svc := &Service{store: st, cfg: cfg, hc: &http.Client{Timeout: 15 * time.Second}, admin: admin}
	if cfg.OIDC != nil {
		svc.oidc = newOIDCState(cfg.OIDC)
	}
	return svc
}

// ParseAdminIDs parses the ADMIN_GITHUB_IDS value: comma-separated positive
// GitHub numeric ids. Whitespace around entries and empty entries are ignored;
// an empty value means no admins. Anything non-numeric is an error, because
// silently dropping an entry would hide a typo in a security setting.
func ParseAdminIDs(v string) ([]int64, error) {
	var out []int64
	seen := map[int64]bool{}
	for _, f := range strings.Split(v, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		id, err := strconv.ParseInt(f, 10, 64)
		if err != nil || id <= 0 {
			return nil, fmt.Errorf("ADMIN_GITHUB_IDS: %q is not a GitHub numeric user id (use ids, not logins; e.g. ADMIN_GITHUB_IDS=139420415)", f)
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

// IsAdmin reports whether GitHub user id is configured as an admin.
func (s *Service) IsAdmin(id int64) bool { return s.admin[id] }

// register is the single list of routes (see api.API.register).
func (s *Service) register(handle func(pattern string, h func(http.ResponseWriter, *http.Request))) {
	handle("POST /v1/auth/device", s.device)
	handle("POST /v1/auth/token", s.token)
	handle("POST /v1/auth/oidc", s.oidcExchange)
	handle("GET /v1/auth/me", s.me)
	handle("GET /v1/auth/orgs", s.listOrgs)
	handle("GET /v1/auth/usage", s.usage)
	handle("GET /v1/auth/tokens", s.listTokens)
	handle("DELETE /v1/auth/tokens/current", s.revokeCurrent)
	handle("DELETE /v1/auth/tokens/{id}", s.revokeToken)
}

// Routes lists the patterns Handler serves ("METHOD /path").
func (s *Service) Routes() []string {
	var out []string
	s.register(func(p string, _ func(http.ResponseWriter, *http.Request)) { out = append(out, p) })
	return out
}

// Handler serves /v1/auth/*.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	s.register(mux.HandleFunc)
	return mux
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func hashToken(tok string) []byte {
	h := sha256.Sum256([]byte(tok))
	return h[:]
}

// bearerHash extracts the bearer token from r and returns its hash.
func bearerHash(r *http.Request) ([]byte, bool) {
	h := r.Header.Get("Authorization")
	scheme, tok, found := strings.Cut(h, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || tok == "" {
		return nil, false
	}
	return hashToken(strings.TrimSpace(tok)), true
}

// lookupBearer resolves the request's bearer token, whatever its scope.
// Unknown, expired, revoked and banned all give the same false, so a caller
// cannot tell them apart. Route handlers must not call this directly: they use
// requireFull, which refuses scoped tokens, so that a route written later is
// closed to them by default.
func (s *Service) lookupBearer(r *http.Request) (store.Token, []byte, bool) {
	hash, ok := bearerHash(r)
	if !ok {
		return store.Token{}, nil, false
	}
	tk, err := s.store.LookupToken(hash)
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			log.Printf("auth: token lookup: %v", err)
		}
		return store.Token{}, nil, false
	}
	// A banned user's existing tokens stop working. Fail closed if the check
	// itself errors.
	banned, err := s.store.IsBanned(tk.UserID)
	if err != nil {
		log.Printf("auth: ban lookup: %v", err)
		return store.Token{}, nil, false
	}
	if banned {
		return store.Token{}, nil, false
	}
	s.store.TouchToken(tk) // at most hourly; never fails the request
	return tk, hash, true
}

// requireFull authenticates a route that needs a full-power token: it writes
// 401 for no valid token and 403 for a scoped one.
func (s *Service) requireFull(w http.ResponseWriter, r *http.Request) (store.Token, []byte, bool) {
	tk, hash, ok := s.lookupBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "authentication required")
		return store.Token{}, nil, false
	}
	if tk.Scope != "" {
		writeErr(w, http.StatusForbidden, "this token is publish-scoped (issued to a CI workflow) and can only publish bundles under its own login")
		return store.Token{}, nil, false
	}
	return tk, hash, true
}

// Authenticate resolves "Authorization: Bearer <token>" to the GitHub id and
// current login of the token's owner. It answers ok only for a full-power
// token: a scoped token is not accepted by anything still using this
// signature (AuthenticateDetail carries the scope for callers that handle it).
func (s *Service) Authenticate(r *http.Request) (int64, string, bool) {
	tk, _, ok := s.lookupBearer(r)
	if !ok || tk.Scope != "" {
		return 0, "", false
	}
	return tk.UserID, tk.Login, true
}

// AuthenticateDetail is Authenticate for the API package: it also returns
// scoped tokens, with their scope and claims, and the API decides what each
// scope may call.
func (s *Service) AuthenticateDetail(r *http.Request) (store.Token, bool) {
	tk, _, ok := s.lookupBearer(r)
	return tk, ok
}

func (s *Service) configured(w http.ResponseWriter) bool {
	if s.cfg.ClientID == "" {
		writeErr(w, http.StatusServiceUnavailable, "authentication is not configured on this server (GITHUB_CLIENT_ID is unset)")
		return false
	}
	return true
}

// postForm POSTs form values to GitHub asking for JSON and decodes the reply.
func (s *Service) postForm(path string, form url.Values, out any) error {
	req, err := http.NewRequest("POST", s.cfg.OAuthURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := s.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("github returned status " + resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func (s *Service) device(w http.ResponseWriter, r *http.Request) {
	if !s.configured(w) {
		return
	}
	var gh struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		Interval        int    `json:"interval"`
		ExpiresIn       int    `json:"expires_in"`
		Error           string `json:"error"`
	}
	// `capm login --orgs` sends {"orgs": true}; any other body (an older CLI
	// sends {} or nothing) means a plain login, which asks GitHub for no scope.
	var in struct {
		Orgs bool `json:"orgs"`
	}
	if b, err := io.ReadAll(io.LimitReader(r.Body, 1<<16)); err == nil {
		json.Unmarshal(b, &in) // a body that does not parse is a plain login
	}
	form := url.Values{"client_id": {s.cfg.ClientID}}
	if in.Orgs {
		form.Set("scope", scopeReadOrg)
	}
	if err := s.postForm("/login/device/code", form, &gh); err != nil {
		log.Printf("auth: device start: %v", err)
		writeErr(w, http.StatusBadGateway, "could not reach GitHub")
		return
	}
	if gh.Error != "" || gh.DeviceCode == "" {
		log.Printf("auth: device start rejected: %q", gh.Error)
		writeErr(w, http.StatusBadGateway, "GitHub rejected the device flow request")
		return
	}
	out := map[string]any{
		"device_code":      gh.DeviceCode,
		"user_code":        gh.UserCode,
		"verification_uri": gh.VerificationURI,
		"interval":         gh.Interval,
		"expires_in":       gh.ExpiresIn,
	}
	if in.Orgs {
		// Echoed so a CLI can tell a registry that supports --orgs from an
		// older one that ignored the request.
		out["scope"] = scopeReadOrg
	}
	writeJSON(w, 200, out)
}

func (s *Service) token(w http.ResponseWriter, r *http.Request) {
	if !s.configured(w) {
		return
	}
	var in struct {
		DeviceCode string `json:"device_code"`
		Name       string `json:"name"` // optional; older CLIs send none
		// Orgs is set by `capm login --orgs`. It only asks for the
		// organisation check; what is recorded comes from GitHub alone.
		Orgs bool `json:"orgs"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil || in.DeviceCode == "" {
		writeErr(w, http.StatusBadRequest, "device_code is required")
		return
	}
	var gh struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
		Error       string `json:"error"`
	}
	err := s.postForm("/login/oauth/access_token", url.Values{
		"client_id":   {s.cfg.ClientID},
		"device_code": {in.DeviceCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}, &gh)
	if err != nil {
		log.Printf("auth: token exchange: %v", err)
		writeErr(w, http.StatusBadGateway, "could not reach GitHub")
		return
	}
	switch gh.Error {
	case "":
	case "authorization_pending":
		writeErr(w, http.StatusPreconditionRequired, "authorization_pending")
		return
	case "slow_down":
		writeErr(w, http.StatusTooManyRequests, "slow_down")
		return
	case "expired_token":
		writeErr(w, http.StatusBadRequest, "expired_token")
		return
	case "access_denied":
		writeErr(w, http.StatusForbidden, "access_denied")
		return
	default:
		log.Printf("auth: github error %q", gh.Error)
		writeErr(w, http.StatusBadGateway, "GitHub rejected the authorization")
		return
	}
	if gh.AccessToken == "" {
		writeErr(w, http.StatusBadGateway, "GitHub returned no access token")
		return
	}

	id, login, err := s.githubUser(gh.AccessToken)
	if err != nil {
		log.Printf("auth: fetch user: %v", err)
		writeErr(w, http.StatusBadGateway, "could not fetch your GitHub profile")
		return
	}
	// The device start step cannot know who is logging in; this is the first
	// point the user id is known. Refuse before writing anything.
	banned, err := s.store.IsBanned(id)
	if err != nil {
		log.Printf("auth: ban lookup: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	if banned {
		writeErr(w, http.StatusForbidden, "this account is banned from the registry")
		return
	}
	if err := s.store.UpsertUser(id, login); err != nil {
		log.Printf("auth: upsert user: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		log.Printf("auth: rand: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)
	if err := s.store.CreateToken(hashToken(tok), id, cleanTokenName(in.Name), s.expiry()); err != nil {
		log.Printf("auth: store token: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := map[string]any{"token": tok}
	if in.Orgs {
		// The GitHub access token is still in hand here and is dropped when
		// this handler returns: never stored, never logged.
		out["orgs"] = s.recordOrgs(gh.AccessToken, gh.Scope, id)
	}
	writeJSON(w, 200, out)
}

// maxTokenName caps a token's name, in characters.
const maxTokenName = 64

// cleanTokenName makes a client-supplied token name safe to store and later
// print: valid UTF-8, no control characters, trimmed, at most 64 characters.
func cleanTokenName(n string) string {
	n = strings.ToValidUTF8(n, "")
	n = strings.Map(func(r rune) rune {
		// U+FFFD is what JSON decoding turns invalid UTF-8 into.
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, n)
	n = strings.TrimSpace(n)
	if r := []rune(n); len(r) > maxTokenName {
		n = strings.TrimSpace(string(r[:maxTokenName]))
	}
	return n
}

// expiry is the expiry for a token issued now; the zero time means never.
func (s *Service) expiry() time.Time {
	if s.cfg.TokenTTL <= 0 {
		return time.Time{}
	}
	return time.Now().Add(s.cfg.TokenTTL)
}

// usage reports the caller's storage usage and the limits that apply to them
// (0 = unlimited).
func (s *Service) usage(w http.ResponseWriter, r *http.Request) {
	tk, _, ok := s.requireFull(w, r)
	if !ok {
		return
	}
	// ?owner=<login> shows an organisation's usage to the members who may
	// publish under it; it goes through the same function as publish and yank.
	who := tk.UserID
	if owner := r.URL.Query().Get("owner"); owner != "" {
		acc, den, err := s.store.AuthorizeOwner(tk, owner, store.ActRead)
		if err != nil {
			log.Printf("auth: usage owner: %v", err)
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		if den != nil {
			writeErr(w, http.StatusForbidden, "you may only see the usage of your own account or of an organisation you may publish under")
			return
		}
		who = acc.Owner.ID
	}
	u, err := s.store.Usage(who)
	if err != nil {
		log.Printf("auth: usage: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, 200, map[string]int64{"bytes": u.Bytes, "maxBytes": u.MaxBytes,
		"bundles": u.Bundles, "maxBundles": u.MaxBundles, "maxBundleVersions": u.MaxBundleVersions})
}

// me reports the identity a bearer token belongs to.
func (s *Service) me(w http.ResponseWriter, r *http.Request) {
	tk, _, ok := s.requireFull(w, r)
	if !ok {
		return
	}
	out := map[string]any{"id": tk.UserID, "login": tk.Login, "tokenId": tk.ID}
	if !tk.ExpiresAt.IsZero() {
		out["tokenExpiresAt"] = tk.ExpiresAt.Format(time.RFC3339)
	}
	writeJSON(w, 200, out)
}

type tokenJSON struct {
	ID         int64   `json:"id"`
	Name       string  `json:"name"`
	CreatedAt  string  `json:"createdAt"`
	LastUsedAt *string `json:"lastUsedAt,omitempty"`
	ExpiresAt  *string `json:"expiresAt,omitempty"`
	Current    bool    `json:"current"`
	// Scope is present only for scoped (CI) tokens.
	Scope string `json:"scope,omitempty"`
}

func rfc3339Ptr(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	v := t.Format(time.RFC3339)
	return &v
}

// listTokens lists the caller's usable tokens. It never includes hashes.
func (s *Service) listTokens(w http.ResponseWriter, r *http.Request) {
	tk, hash, ok := s.requireFull(w, r)
	if !ok {
		return
	}
	list, err := s.store.ListTokens(tk.UserID, hash)
	if err != nil {
		log.Printf("auth: list tokens: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]tokenJSON, 0, len(list))
	for _, t := range list {
		out = append(out, tokenJSON{t.ID, t.Name, t.CreatedAt.Format(time.RFC3339),
			rfc3339Ptr(t.LastUsedAt), rfc3339Ptr(t.ExpiresAt), t.Current, t.Scope})
	}
	writeJSON(w, 200, out)
}

// revokeToken revokes one of the caller's own tokens by id. Another user's
// token, an unknown id and a malformed id all answer 404.
func (s *Service) revokeToken(w http.ResponseWriter, r *http.Request) {
	tk, _, ok := s.requireFull(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	switch err := s.store.RevokeToken(tk.UserID, id); {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, store.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	default:
		log.Printf("auth: revoke token: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

// revokeCurrent revokes the token that signed the request (capm logout).
func (s *Service) revokeCurrent(w http.ResponseWriter, r *http.Request) {
	tk, _, ok := s.requireFull(w, r)
	if !ok {
		return
	}
	if err := s.store.RevokeToken(tk.UserID, tk.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
		log.Printf("auth: revoke current: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) githubUser(accessToken string) (int64, string, error) {
	req, err := http.NewRequest("GET", s.cfg.APIURL+"/user", nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := s.hc.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return 0, "", errors.New("github /user returned status " + resp.Status)
	}
	var u struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&u); err != nil {
		return 0, "", err
	}
	if u.ID <= 0 || u.Login == "" || strings.HasPrefix(u.Login, "~") {
		return 0, "", errors.New("github /user returned an invalid identity")
	}
	return u.ID, u.Login, nil
}
