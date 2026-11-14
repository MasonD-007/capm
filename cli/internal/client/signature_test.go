package client_test

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/MasonD-007/capm/cli/internal/client"
)

func TestSignatureReturnsStoredBytesAndSendsNoToken(t *testing.T) {
	const body = " {\"b\": 1,\n \"a\":2}\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.EscapedPath() != "/v1/bundles/alice/my%20x/1.0.0/signature" {
			t.Errorf("%s %s", r.Method, r.URL)
		}
		if r.Header.Get("Authorization") != "" {
			t.Errorf("a token was sent: %q", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, body)
	}))
	defer srv.Close()
	got, err := client.New(srv.URL, "secret-token").Signature("alice", "my x", "1.0.0")
	if err != nil || string(got) != body {
		t.Fatalf("%q %v", got, err)
	}
}

func TestSignatureNotFoundIsTyped(t *testing.T) {
	for _, code := range []int{404} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			io.WriteString(w, `{"error":"no signature"}`)
		}))
		_, err := client.New(srv.URL, "").Signature("alice", "x", "1.0.0")
		srv.Close()
		if !errors.Is(err, client.ErrNoSignature) {
			t.Fatalf("404: %v", err)
		}
	}
	// A plain 404 from an older registry (no such route) is the same.
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	if _, err := client.New(srv.URL, "").Signature("alice", "x", "1.0.0"); !errors.Is(err, client.ErrNoSignature) {
		t.Fatalf("old registry: %v", err)
	}
}

func TestSignatureOtherErrorsAreNotNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		io.WriteString(w, `{"error":"internal error"}`)
	}))
	defer srv.Close()
	_, err := client.New(srv.URL, "").Signature("alice", "x", "1.0.0")
	var ae *client.APIError
	if err == nil || errors.Is(err, client.ErrNoSignature) || !errors.As(err, &ae) || ae.Status != 500 {
		t.Fatalf("%v", err)
	}
}

func TestSignatureResponseIsCappedAt64KiB(t *testing.T) {
	var size int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte("a"), size))
	}))
	defer srv.Close()
	c := client.New(srv.URL, "")
	size = 64 << 10
	if b, err := c.Signature("a", "x", "1.0.0"); err != nil || len(b) != 64<<10 {
		t.Fatalf("at cap: %d %v", len(b), err)
	}
	size = 64<<10 + 1
	if _, err := c.Signature("a", "x", "1.0.0"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("over cap: %v", err)
	}
}

func TestPutSignatureSendsBytesJSONAndToken(t *testing.T) {
	const body = " {\"x\" :1}\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if r.Method != "PUT" || r.URL.Path != "/v1/bundles/alice/x/1.0.0/signature" ||
			r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Authorization") != "Bearer tok" || string(b) != body {
			t.Errorf("%s %s %q %q %q", r.Method, r.URL.Path, r.Header.Get("Content-Type"), r.Header.Get("Authorization"), b)
		}
		w.WriteHeader(201)
		io.WriteString(w, "{}\n")
	}))
	defer srv.Close()
	if err := client.New(srv.URL, "tok").PutSignature("alice", "x", "1.0.0", []byte(body)); err != nil {
		t.Fatal(err)
	}
}

func TestPutSignatureErrorsCarryStatus(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 409, 413} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
			io.WriteString(w, `{"error":"nope"}`)
		}))
		err := client.New(srv.URL, "tok").PutSignature("alice", "x", "1.0.0", []byte(`{}`))
		srv.Close()
		var ae *client.APIError
		if !errors.As(err, &ae) || ae.Status != code {
			t.Errorf("%d: %v", code, err)
		}
	}
}

func TestSignedDecodesInVersionsMetadataAndList(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/bundles":
			io.WriteString(w, `[{"owner":"alice","name":"x","latest":"1.0.0","signed":true},{"owner":"alice","name":"y","latest":"1.0.0"}]`)
		case "/v1/bundles/alice/x":
			io.WriteString(w, `[{"version":"1.0.0","signed":true},{"version":"1.1.0","signed":false},{"version":"1.2.0"}]`)
		default:
			io.WriteString(w, `{"version":"1.0.0","signed":true}`)
		}
	}))
	defer srv.Close()
	c := client.New(srv.URL, "")
	bs, err := c.ListBundles("", "", 10, 0)
	if err != nil || len(bs) != 2 || !bs[0].Signed || bs[1].Signed {
		t.Fatalf("%+v %v", bs, err)
	}
	vs, err := c.Versions("alice", "x")
	if err != nil || len(vs) != 3 || !vs[0].Signed || vs[1].Signed || vs[2].Signed {
		t.Fatalf("%+v %v", vs, err)
	}
	m, err := c.Metadata("alice", "x", "1.0.0")
	if err != nil || !m.Signed {
		t.Fatalf("%+v %v", m, err)
	}
}
