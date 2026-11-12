package client_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MasonD-007/capm/cli/internal/client"
)

func TestIsUnsupported(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
		want   bool
	}{
		"old server 404":  {404, "404 page not found\n", true},
		"old server 405":  {405, "", true},
		"new server 404":  {404, `{"error":"not found"}`, false},
		"unauthenticated": {401, `{"error":"authentication required"}`, false},
		"server error":    {500, `{"error":"internal error"}`, false},
	}
	for name, c := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(c.status)
			io.WriteString(w, c.body)
		}))
		_, err := client.New(srv.URL, "tok").Tokens()
		srv.Close()
		if got := client.IsUnsupported(err); got != c.want {
			t.Errorf("%s: IsUnsupported = %v, want %v (err %v)", name, got, c.want, err)
		}
	}
	if client.IsUnsupported(nil) || client.IsUnsupported(io.EOF) {
		t.Error("non-API errors are not 'unsupported'")
	}
}
