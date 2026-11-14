package client_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MasonD-007/capm/cli/internal/client"
)

func TestFetchSignature(t *testing.T) {
	var gotPath, gotAuth string
	handler := func(code int, body string) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath, gotAuth = r.URL.EscapedPath(), r.Header.Get("Authorization")
			w.WriteHeader(code)
			io.WriteString(w, body)
		})
	}
	cases := []struct {
		name      string
		code      int
		body      string
		wantFound bool
		wantErr   bool
	}{
		{"200", 200, `{"mediaType":"x"}`, true, false},
		{"404 is unsigned, not an error", 404, `{"error":"no signature"}`, false, false},
		{"404 plain text (mux)", 404, "404 page not found", false, false},
		{"500", 500, `{"error":"boom"}`, false, true},
		{"503", 503, ``, false, true},
		{"403", 403, ``, false, true},
		{"410", 410, `{"error":"gone"}`, false, true},
		{"204", 204, ``, false, true},
		{"exactly the cap", 200, strings.Repeat("a", client.MaxSignatureBytes), true, false},
		{"one byte over the cap", 200, strings.Repeat("a", client.MaxSignatureBytes+1), false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(handler(tc.code, tc.body))
			defer srv.Close()
			// A token on the client must not be sent: signatures are public.
			c := client.New(srv.URL, "secret-token")
			b, found, err := c.FetchSignature("al ice", "na/me", "1.0.0")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, want error %v", err, tc.wantErr)
			}
			if found != tc.wantFound {
				t.Errorf("found = %v, want %v", found, tc.wantFound)
			}
			if tc.wantFound && string(b) != tc.body {
				t.Errorf("body mismatch (%d bytes)", len(b))
			}
			if !tc.wantFound && b != nil {
				t.Errorf("bytes returned without found: %d", len(b))
			}
			if gotPath != "/v1/bundles/al%20ice/na%2Fme/1.0.0/signature" {
				t.Errorf("path %q", gotPath)
			}
			if gotAuth != "" {
				t.Errorf("Authorization sent: %q", gotAuth)
			}
		})
	}
}

func TestFetchSignatureTransportErrorIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	_, found, err := client.New(url, "").FetchSignature("a", "b", "1.0.0")
	if err == nil || found {
		t.Fatalf("found=%v err=%v", found, err)
	}
}

func TestFetchSignatureRedirects(t *testing.T) {
	var otherHits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		io.WriteString(w, "bundle from elsewhere")
	}))
	defer other.Close()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/bundles/a/b/1.0.0/signature", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/sig", http.StatusFound)
	})
	mux.HandleFunc("/v1/bundles/a/same/1.0.0/signature", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere-on-this-host", http.StatusFound)
	})
	mux.HandleFunc("/elsewhere-on-this-host", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "same-host bundle")
	})
	mux.HandleFunc("/v1/bundles/a/loop/1.0.0/signature", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, r.URL.Path, http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := client.New(srv.URL, "")

	if _, found, err := c.FetchSignature("a", "b", "1.0.0"); err == nil || found {
		t.Errorf("cross-host redirect followed: found=%v err=%v", found, err)
	}
	if otherHits.Load() != 0 {
		t.Error("the other host was contacted")
	}
	b, found, err := c.FetchSignature("a", "same", "1.0.0")
	if err != nil || !found || string(b) != "same-host bundle" {
		t.Errorf("same-host redirect: %q %v %v", b, found, err)
	}
	if _, found, err := c.FetchSignature("a", "loop", "1.0.0"); err == nil || found {
		t.Errorf("redirect loop: found=%v err=%v", found, err)
	}
}

func TestMetadataWithSigned(t *testing.T) {
	for _, tc := range []struct {
		body string
		want string // "true", "false" or "absent"
	}{
		{`{"version":"1.0.0","signed":true}`, "true"},
		{`{"version":"1.0.0","signed":false}`, "false"},
		{`{"version":"1.0.0"}`, "absent"}, // an older server
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, tc.body)
		}))
		m, signed, err := client.New(srv.URL, "").MetadataWithSigned("a", "b", "1.0.0")
		srv.Close()
		got := "absent"
		if signed != nil {
			got = fmt.Sprint(*signed)
		}
		if err != nil || got != tc.want || m.Version != "1.0.0" {
			t.Errorf("%s: %+v signed=%v err=%v", tc.body, m, got, err)
		}
	}
}
