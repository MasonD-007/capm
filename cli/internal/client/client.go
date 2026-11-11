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
}

type Resolved struct {
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
}

func (e *APIError) Error() string {
	return fmt.Sprintf("registry error (%d): %s", e.Status, Sanitize(e.Msg))
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
		if strings.Contains(path, "/auth/") {
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
			Error string `json:"error"`
		}
		msg := ""
		if json.Unmarshal(b, &e) == nil {
			msg = e.Error
		}
		if msg == "" {
			msg = http.StatusText(resp.StatusCode)
		}
		return nil, &APIError{Status: resp.StatusCode, Msg: msg}
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
	body, _ := json.Marshal(map[string]string{"device_code": deviceCode})
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
