// Package client talks to a capm registry over HTTP.
package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/MasonD-007/capm/manifest"
)

const (
	MaxJSONBytes    = 1 << 20  // cap on JSON responses
	MaxTarballBytes = 16 << 20 // cap on downloaded bundles
)

type DeviceCode struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	Interval        int    `json:"interval"`
	ExpiresIn       int    `json:"expires_in"`
}

type Identity struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	// TokenID and TokenExpiresAt (RFC 3339, empty = never expires) describe the
	// token that made the request. Older registries send neither.
	TokenID        int64  `json:"tokenId"`
	TokenExpiresAt string `json:"tokenExpiresAt"`
}

// TokenInfo is one entry of GET /v1/auth/tokens. The registry never sends the
// token itself or its hash. Name is untrusted.
type TokenInfo struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	CreatedAt  time.Time  `json:"createdAt"`
	LastUsedAt *time.Time `json:"lastUsedAt"`
	ExpiresAt  *time.Time `json:"expiresAt"`
	Current    bool       `json:"current"`
}

type Resolved struct {
	// OwnerID is the owner's numeric account id; 0 when an older server omits it.
	OwnerID int64  `json:"ownerId,omitempty"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
	Yanked  bool   `json:"yanked"`
	Warning string `json:"warning,omitempty"`
}

// Metadata is what GET /v1/bundles/{owner}/{name}/{version} reports about one
// version. The server also sends a precomputed `summary`; it is deliberately
// not decoded, because the caller recomputes it from the manifest rather than
// trusting the registry's rendering.
type Metadata struct {
	OwnerID   int64             `json:"ownerId,omitempty"`
	Version   string            `json:"version"`
	Digest    string            `json:"digest"`
	Yanked    bool              `json:"yanked"`
	Manifest  manifest.Manifest `json:"manifest"`
	CreatedAt time.Time         `json:"createdAt"`
}

type VersionInfo struct {
	Version   string    `json:"version"`
	Digest    string    `json:"digest"`
	Yanked    bool      `json:"yanked"`
	CreatedAt time.Time `json:"createdAt"`
}

// BundleInfo is one entry of GET /v1/bundles. Latest is empty when every
// version is yanked; Description belongs to Latest and is unverified.
type BundleInfo struct {
	Owner       string `json:"owner"`
	Name        string `json:"name"`
	Latest      string `json:"latest"`
	Description string `json:"description"`
	// Risk is the registry's claim of the highest risk label severity of
	// Latest ("high", "caution", "info" or ""); empty from an older server.
	// It is untrusted and only drives the list marker; `capm inspect`
	// recomputes labels from the manifest. The server's riskLabels are
	// deliberately not decoded.
	Risk string `json:"risk"`
}

// Sanitize makes a server-supplied string safe to print on a terminal: C0
// controls (including ESC and newlines), DEL, C1 controls, line/paragraph
// separators and bidi controls (manifest.IsUnsafeRune) are dropped and the
// result is truncated to 200 runes.
func Sanitize(s string) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if manifest.IsUnsafeRune(r) {
			continue
		}
		if n++; n > 200 {
			b.WriteString("...")
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// APIError is a non-2xx response from the registry.
type APIError struct {
	Status int
	Msg    string
	// Limit names the quota that rejected a publish ("user_bytes",
	// "user_bundles", "bundle_versions", "total_bytes"); empty for every other
	// error, including the plain "bundle too large" 413.
	Limit string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("registry error (%d): %s", e.Status, Sanitize(e.Msg))
}

// RemovedError is a 410 Gone: an admin took the version down. Reason is the
// admin's text and untrusted; Error() sanitises it for the terminal.
type RemovedError struct {
	Reason string
}

func (e *RemovedError) Error() string {
	if r := Sanitize(e.Reason); r != "" {
		return "removed by the registry: " + r
	}
	return "removed by the registry"
}

type Client struct {
	base  string
	token string
	hc    *http.Client

	// Sleep and PollInterval drive PollToken; tests replace Sleep.
	Sleep        func(time.Duration)
	PollInterval time.Duration
	// PollTimeout bounds the total time PollToken waits (0 = 15 minutes).
	PollTimeout time.Duration
	// TokenName labels the token PollToken obtains (e.g. the hostname).
	TokenName string
}

func New(baseURL, token string) *Client {
	return &Client{
		base:         strings.TrimRight(baseURL, "/"),
		token:        token,
		hc:           &http.Client{Timeout: 30 * time.Second},
		Sleep:        time.Sleep,
		PollInterval: 5 * time.Second,
	}
}

func esc(parts ...string) string {
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = url.PathEscape(p)
	}
	return strings.Join(out, "/")
}

// do sends a request and returns the body of a 2xx response, capped at max
// bytes. Non-2xx responses become *APIError carrying the server's message.
func (c *Client) do(method, path string, body []byte, max int64) ([]byte, error) {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		if strings.Contains(path, "/auth/") || strings.Contains(path, "/admin/") {
			req.Header.Set("Content-Type", "application/json")
		} else {
			req.Header.Set("Content-Type", "application/gzip")
		}
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	limit := max
	if resp.StatusCode/100 != 2 {
		limit = MaxJSONBytes
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("registry response exceeds %d bytes", limit)
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error  string `json:"error"`
			Reason string `json:"reason"`
			Limit  string `json:"limit"`
		}
		msg := ""
		if json.Unmarshal(b, &e) == nil {
			msg = e.Error
		}
		if resp.StatusCode == http.StatusGone {
			if e.Reason == "" {
				e.Reason = strings.TrimPrefix(msg, "removed by the registry: ")
			}
			return nil, &RemovedError{Reason: e.Reason}
		}
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return nil, &APIError{Status: resp.StatusCode, Msg: msg, Limit: e.Limit}
	}
	return b, nil
}

func (c *Client) getJSON(path string, out any) error {
	b, err := c.do("GET", path, nil, MaxJSONBytes)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func (c *Client) StartDeviceFlow() (DeviceCode, error) {
	var d DeviceCode
	b, err := c.do("POST", "/v1/auth/device", []byte("{}"), MaxJSONBytes)
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(b, &d); err != nil {
		return d, err
	}
	if d.DeviceCode == "" {
		return d, errors.New("registry returned no device code")
	}
	if d.Interval > 0 {
		c.PollInterval = time.Duration(d.Interval) * time.Second
	}
	if d.ExpiresIn > 0 {
		c.PollTimeout = time.Duration(d.ExpiresIn) * time.Second
	}
	return d, nil
}

// PollToken polls until the user authorizes the device code and returns the
// capm API token. It waits PollInterval between polls and backs off on slow_down.
func (c *Client) PollToken(deviceCode string) (string, error) {
	req := map[string]string{"device_code": deviceCode}
	if c.TokenName != "" {
		req["name"] = c.TokenName
	}
	body, _ := json.Marshal(req)
	timeout := c.PollTimeout
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	interval := c.PollInterval
	if interval <= 0 {
		interval = 5 * time.Second
	}
	var waited time.Duration
	for {
		b, err := c.do("POST", "/v1/auth/token", body, MaxJSONBytes)
		if err == nil {
			var out struct {
				Token string `json:"token"`
			}
			if err := json.Unmarshal(b, &out); err != nil || out.Token == "" {
				return "", errors.New("registry returned no token")
			}
			return out.Token, nil
		}
		var ae *APIError
		if !errors.As(err, &ae) {
			return "", err
		}
		switch ae.Msg {
		case "authorization_pending":
		case "slow_down":
			interval += 5 * time.Second
		default:
			return "", fmt.Errorf("login failed: %s", Sanitize(ae.Msg))
		}
		if waited >= timeout {
			return "", errors.New("login timed out; run capm login again")
		}
		c.Sleep(interval)
		waited += interval
	}
}

// Me returns the identity the client's token belongs to.
func (c *Client) Me() (Identity, error) {
	var id Identity
	err := c.getJSON("/v1/auth/me", &id)
	return id, err
}

// IsUnsupported reports whether err means the registry predates token
// management: the route does not exist (a 404 that is not the new server's own
// JSON "not found") or the method is not allowed.
func IsUnsupported(err error) bool {
	var ae *APIError
	if !errors.As(err, &ae) {
		return false
	}
	return ae.Status == http.StatusMethodNotAllowed || (ae.Status == http.StatusNotFound && ae.Msg != "not found")
}

// Tokens lists the caller's active tokens.
func (c *Client) Tokens() ([]TokenInfo, error) {
	var out []TokenInfo
	err := c.getJSON("/v1/auth/tokens", &out)
	return out, err
}

// RevokeToken revokes one of the caller's tokens by id.
func (c *Client) RevokeToken(id int64) error {
	_, err := c.do("DELETE", "/v1/auth/tokens/"+strconv.FormatInt(id, 10), nil, MaxJSONBytes)
	return err
}

// RevokeCurrentToken revokes the token this client authenticates with.
func (c *Client) RevokeCurrentToken() error {
	_, err := c.do("DELETE", "/v1/auth/tokens/current", nil, MaxJSONBytes)
	return err
}

// AdminRevokeTokens revokes every token of a user (login or numeric id) and
// returns how many were revoked.
func (c *Client) AdminRevokeTokens(user string) (int, error) {
	var out struct {
		Revoked int `json:"revoked"`
	}
	err := c.adminJSON("DELETE", "/v1/admin/users/"+esc(user)+"/tokens", nil, &out)
	return out.Revoked, err
}

// Usage is the caller's storage use and limits (a Max of 0 means unlimited).
type Usage struct {
	Bytes             int64 `json:"bytes"`
	MaxBytes          int64 `json:"maxBytes"`
	Bundles           int64 `json:"bundles"`
	MaxBundles        int64 `json:"maxBundles"`
	MaxBundleVersions int64 `json:"maxBundleVersions"`
}

// Usage fetches the caller's usage. A registry that predates quotas answers
// with an error for which IsUnsupported is true.
func (c *Client) Usage() (Usage, error) {
	var u Usage
	err := c.getJSON("/v1/auth/usage", &u)
	return u, err
}

// Quota is an admin's view of one user's usage and limits.
type Quota struct {
	ID                int64 `json:"id"`
	Bytes             int64 `json:"bytes"`
	MaxBytes          int64 `json:"maxBytes"`
	Bundles           int64 `json:"bundles"`
	MaxBundles        int64 `json:"maxBundles"`
	MaxBundleVersions int64 `json:"maxBundleVersions"`
	BytesOverridden   bool  `json:"bytesOverridden"`
	BundlesOverridden bool  `json:"bundlesOverridden"`
}

// AdminQuota shows a user's (login or numeric id) usage and limits.
func (c *Client) AdminQuota(user string) (Quota, error) {
	var q Quota
	err := c.getJSON("/v1/admin/users/"+esc(user)+"/quota", &q)
	return q, err
}

// AdminSetQuota replaces a user's overrides; nil clears that override (the
// default applies) and 0 means unlimited.
func (c *Client) AdminSetQuota(user string, maxBytes, maxBundles *int64) (Quota, error) {
	var q Quota
	err := c.adminJSON("PUT", "/v1/admin/users/"+esc(user)+"/quota",
		map[string]*int64{"maxBytes": maxBytes, "maxBundles": maxBundles}, &q)
	return q, err
}

func (c *Client) Publish(owner, name, version string, tarball []byte) error {
	_, err := c.do("PUT", "/v1/bundles/"+esc(owner, name, version), tarball, MaxJSONBytes)
	return err
}

// Resolve maps a spec ("latest" or an exact version) to a version.
func (c *Client) Resolve(owner, name, spec string) (Resolved, error) {
	var r Resolved
	err := c.getJSON("/v1/bundles/"+esc(owner, name)+"/resolve?range="+url.QueryEscape(spec), &r)
	return r, err
}

// Metadata fetches the manifest and digest of an exact version without
// downloading the bundle.
func (c *Client) Metadata(owner, name, version string) (Metadata, error) {
	var m Metadata
	err := c.getJSON("/v1/bundles/"+esc(owner, name, version), &m)
	return m, err
}

func (c *Client) Download(owner, name, version string) ([]byte, error) {
	return c.do("GET", "/v1/bundles/"+esc(owner, name, version)+"/download", nil, MaxTarballBytes)
}

func (c *Client) Versions(owner, name string) ([]VersionInfo, error) {
	var v []VersionInfo
	err := c.getJSON("/v1/bundles/"+esc(owner, name), &v)
	return v, err
}

// ListBundles returns one page of bundles; q and owner are optional filters.
func (c *Client) ListBundles(q, owner string, limit, offset int) ([]BundleInfo, error) {
	v := url.Values{}
	v.Set("limit", strconv.Itoa(limit))
	v.Set("offset", strconv.Itoa(offset))
	if q != "" {
		v.Set("q", q)
	}
	if owner != "" {
		v.Set("owner", owner)
	}
	var out []BundleInfo
	err := c.getJSON("/v1/bundles?"+v.Encode(), &out)
	return out, err
}

// AdminAction is one row of the admin audit log.
type AdminAction struct {
	ID        int64     `json:"id"`
	AdminID   int64     `json:"adminId"`
	Admin     string    `json:"admin"`
	Action    string    `json:"action"`
	Target    string    `json:"target"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"createdAt"`
}

// AdminResult is the registry's reply to an admin remove or restore.
type AdminResult struct {
	Versions     []string `json:"versions"`
	BlobsDeleted int      `json:"blobsDeleted"`
	Restored     []string `json:"restored"`
	Skipped      []string `json:"skipped"`
}

func bundlePath(owner, name, version string) string {
	if version == "" {
		return "/v1/admin/bundles/" + esc(owner, name) + "/remove"
	}
	return "/v1/admin/bundles/" + esc(owner, name, version) + "/remove"
}

func (c *Client) adminJSON(method, path string, body any, out any) error {
	var rb []byte
	if body != nil {
		rb, _ = json.Marshal(body)
	}
	b, err := c.do(method, path, rb, MaxJSONBytes)
	if err != nil || out == nil {
		return err
	}
	return json.Unmarshal(b, out)
}

// AdminRemove takes down one version, or every version when version is "".
func (c *Client) AdminRemove(owner, name, version, reason string) (AdminResult, error) {
	var r AdminResult
	err := c.adminJSON("POST", bundlePath(owner, name, version), map[string]string{"reason": reason}, &r)
	return r, err
}

// AdminRestore undoes AdminRemove.
func (c *Client) AdminRestore(owner, name, version string) (AdminResult, error) {
	var r AdminResult
	err := c.adminJSON("DELETE", bundlePath(owner, name, version), nil, &r)
	return r, err
}

// AdminBan bans a user given as a login or a numeric GitHub id.
func (c *Client) AdminBan(user, reason string) error {
	return c.adminJSON("POST", "/v1/admin/users/"+esc(user)+"/ban", map[string]string{"reason": reason}, nil)
}

func (c *Client) AdminUnban(user string) error {
	return c.adminJSON("DELETE", "/v1/admin/users/"+esc(user)+"/ban", nil, nil)
}

func (c *Client) AdminLog(limit int) ([]AdminAction, error) {
	var out []AdminAction
	err := c.getJSON("/v1/admin/log?limit="+strconv.Itoa(limit), &out)
	return out, err
}
