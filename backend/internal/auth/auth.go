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
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MasonD-007/capm/backend/internal/store"
)

type Config struct {
	ClientID string // required for the auth routes to work
	APIURL   string // default https://api.github.com
	OAuthURL string // default https://github.com
}

type Service struct {
	store *store.Store
	cfg   Config
	hc    *http.Client
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
	return &Service{store: st, cfg: cfg, hc: &http.Client{Timeout: 15 * time.Second}}
}

// Handler serves /v1/auth/*.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth/device", s.device)
	mux.HandleFunc("POST /v1/auth/token", s.token)
	mux.HandleFunc("GET /v1/auth/me", s.me)
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

// Authenticate resolves "Authorization: Bearer <token>" to the GitHub id and
// current login of the token's owner.
func (s *Service) Authenticate(r *http.Request) (int64, string, bool) {
	h := r.Header.Get("Authorization")
	scheme, tok, found := strings.Cut(h, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || tok == "" {
		return 0, "", false
	}
	id, login, err := s.store.UserByTokenHash(hashToken(strings.TrimSpace(tok)))
	if err != nil {
		if !errors.Is(err, store.ErrNotFound) {
			log.Printf("auth: token lookup: %v", err)
		}
		return 0, "", false
	}
	return id, login, true
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
	if err := s.postForm("/login/device/code", url.Values{"client_id": {s.cfg.ClientID}}, &gh); err != nil {
		log.Printf("auth: device start: %v", err)
		writeErr(w, http.StatusBadGateway, "could not reach GitHub")
		return
	}
	if gh.Error != "" || gh.DeviceCode == "" {
		log.Printf("auth: device start rejected: %q", gh.Error)
		writeErr(w, http.StatusBadGateway, "GitHub rejected the device flow request")
		return
	}
	writeJSON(w, 200, map[string]any{
		"device_code":      gh.DeviceCode,
		"user_code":        gh.UserCode,
		"verification_uri": gh.VerificationURI,
		"interval":         gh.Interval,
		"expires_in":       gh.ExpiresIn,
	})
}

func (s *Service) token(w http.ResponseWriter, r *http.Request) {
	if !s.configured(w) {
		return
	}
	var in struct {
		DeviceCode string `json:"device_code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&in); err != nil || in.DeviceCode == "" {
		writeErr(w, http.StatusBadRequest, "device_code is required")
		return
	}
	var gh struct {
		AccessToken string `json:"access_token"`
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
	if err := s.store.CreateToken(hashToken(tok), id); err != nil {
		log.Printf("auth: store token: %v", err)
		writeErr(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, 200, map[string]string{"token": tok})
}

// me reports the identity a bearer token belongs to.
func (s *Service) me(w http.ResponseWriter, r *http.Request) {
	id, login, ok := s.Authenticate(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "authentication required")
		return
	}
	writeJSON(w, 200, map[string]any{"id": id, "login": login})
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
