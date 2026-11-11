package client_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/MasonD-007/capm/cli/internal/client"
)

func TestPollTokenPendingSlowDownThenToken(t *testing.T) {
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		var in struct {
			DeviceCode string `json:"device_code"`
		}
		json.NewDecoder(r.Body).Decode(&in)
		if in.DeviceCode != "dc" {
			t.Errorf("device code %q", in.DeviceCode)
		}
		switch n {
		case 1:
			w.WriteHeader(428)
			io.WriteString(w, `{"error":"authorization_pending"}`)
		case 2:
			w.WriteHeader(429)
			io.WriteString(w, `{"error":"slow_down"}`)
		default:
			io.WriteString(w, `{"token":"tok"}`)
		}
	}))
	defer srv.Close()
	var slept []time.Duration
	c := client.New(srv.URL, "")
	c.Sleep = func(d time.Duration) { slept = append(slept, d) }
	c.PollInterval = 5 * time.Second
	tok, err := c.PollToken("dc")
	if err != nil || tok != "tok" {
		t.Fatalf("tok=%q err=%v", tok, err)
	}
	if len(slept) != 2 || slept[1] <= slept[0] {
		t.Fatalf("slow_down should lengthen the interval: %v", slept)
	}
}

func TestPollTokenTerminalErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		io.WriteString(w, `{"error":"access_denied"}`)
	}))
	defer srv.Close()
	c := client.New(srv.URL, "")
	c.Sleep = func(time.Duration) {}
	if _, err := c.PollToken("dc"); err == nil || !strings.Contains(err.Error(), "access_denied") {
		t.Fatalf("err=%v", err)
	}
}

func TestErrorMessageSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		io.WriteString(w, `{"error":"version already exists"}`)
	}))
	defer srv.Close()
	err := client.New(srv.URL, "t").Publish("o", "n", "1.0.0", []byte("x"))
	if err == nil || !strings.Contains(err.Error(), "version already exists") {
		t.Fatalf("err=%v", err)
	}
}

func TestResponseSizeCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(make([]byte, client.MaxJSONBytes+10))
	}))
	defer srv.Close()
	if _, err := client.New(srv.URL, "").Versions("o", "n"); err == nil {
		t.Fatal("expected size error")
	}
}

func TestPathEscaping(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.EscapedPath()
		w.WriteHeader(404)
	}))
	defer srv.Close()
	client.New(srv.URL, "").Download("a/b", "n", "1.0.0")
	if strings.Contains(got, "a/b") {
		t.Fatalf("owner not escaped: %s", got)
	}
}

func TestSanitizeDropsBidiAndSeparators(t *testing.T) {
	in := "a‮b⁦c d\u0085e\x1bf‏g"
	got := client.Sanitize(in)
	for _, r := range []rune{'‮', '⁦', ' ', '\u0085', '\x1b', '‏'} {
		if strings.ContainsRune(got, r) {
			t.Errorf("Sanitize(%q) = %q keeps %U", in, got, r)
		}
	}
	if got != "abcdefg" {
		t.Errorf("Sanitize(%q) = %q, want abcdefg", in, got)
	}
}

func TestListBundlesQueryAndDecode(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.URL.Path + "?" + r.URL.RawQuery
		io.WriteString(w, `[{"ownerId":1,"owner":"alice","name":"x","latest":"1.0.0","description":"d"}]`)
	}))
	defer srv.Close()
	c := client.New(srv.URL, "")

	bs, err := c.ListBundles("a&b=c d%", "Al ice", 200, 400)
	if err != nil {
		t.Fatal(err)
	}
	if want := "/v1/bundles?limit=200&offset=400&owner=Al+ice&q=a%26b%3Dc+d%25"; got != want {
		t.Errorf("request %q, want %q", got, want)
	}
	if len(bs) != 1 || bs[0] != (client.BundleInfo{Owner: "alice", Name: "x", Latest: "1.0.0", Description: "d"}) {
		t.Errorf("decoded %+v", bs)
	}

	// Empty filters are not sent.
	if _, err := c.ListBundles("", "", 5, 0); err != nil {
		t.Fatal(err)
	}
	if want := "/v1/bundles?limit=5&offset=0"; got != want {
		t.Errorf("request %q, want %q", got, want)
	}
}
