package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// MaxSignatureBytes is the largest signature bundle FetchSignature accepts.
// It equals the registry's own cap (and sigverify.MaxBundleSize); real bundles
// are 4-10 KB.
const MaxSignatureBytes = 64 << 10

// maxSignatureRedirects bounds same-host redirects of a signature request.
const maxSignatureRedirects = 3

// FetchSignature downloads the Sigstore bundle attached to owner/name@version.
//
//   - 200: the raw bundle bytes, found = true. A body over MaxSignatureBytes is
//     an error, not a truncated bundle.
//   - 404: no signature (or a registry that predates signatures): found =
//     false, err = nil. Only a 404 means "no signature"; every other status and
//     every transport failure is an error, so that blocking or breaking the
//     request cannot make a signed version look unsigned.
//
// No Authorization header is sent: signatures are public, and the bundle is
// self-authenticating. Redirects are followed only within the registry's own
// scheme and host.
func (c *Client) FetchSignature(owner, name, version string) (bundle []byte, found bool, err error) {
	req, err := http.NewRequest(http.MethodGet, c.base+"/v1/bundles/"+esc(owner, name, version)+"/signature", nil)
	if err != nil {
		return nil, false, err
	}
	hc := &http.Client{
		Timeout:   c.hc.Timeout,
		Transport: c.hc.Transport,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) > maxSignatureRedirects {
				return errors.New("too many redirects")
			}
			first := via[0].URL
			if r.URL.Scheme != first.Scheme || r.URL.Host != first.Host {
				return errors.New("refusing a redirect to a different host")
			}
			return nil
		},
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		b, err := io.ReadAll(io.LimitReader(resp.Body, MaxSignatureBytes+1))
		if err != nil {
			return nil, false, err
		}
		if len(b) > MaxSignatureBytes {
			return nil, false, fmt.Errorf("signature response exceeds %d bytes", MaxSignatureBytes)
		}
		return b, true, nil
	case http.StatusNotFound:
		return nil, false, nil
	}
	// Anything else, including 2xx other than 200: refuse to guess. Read a
	// little of the body only to carry the server's message.
	msg := ""
	if b, _ := io.ReadAll(io.LimitReader(resp.Body, MaxJSONBytes)); len(b) > 0 {
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(b, &e) == nil {
			msg = e.Error
		}
	}
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	return nil, false, &APIError{Status: resp.StatusCode, Msg: msg}
}

// MetadataWithSigned is Metadata plus the registry's `signed` claim for the
// version, decoded here so that Metadata's own struct is untouched. The claim
// is nil when the registry does not send the field (an older server); callers
// treat that as false, but can tell it from an explicit false. The claim is
// advisory and never replaces verifying a signature.
func (c *Client) MetadataWithSigned(owner, name, version string) (Metadata, *bool, error) {
	b, err := c.do("GET", "/v1/bundles/"+esc(owner, name, version), nil, MaxJSONBytes)
	if err != nil {
		return Metadata{}, nil, err
	}
	var m Metadata
	if err := json.Unmarshal(b, &m); err != nil {
		return Metadata{}, nil, err
	}
	var extra struct {
		Signed *bool `json:"signed"`
	}
	if err := json.Unmarshal(b, &extra); err != nil {
		return Metadata{}, nil, err
	}
	return m, extra.Signed, nil
}
