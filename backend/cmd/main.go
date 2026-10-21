package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/MasonD-007/capm/backend/internal/api"
	"github.com/MasonD-007/capm/backend/internal/auth"
	"github.com/MasonD-007/capm/backend/internal/store"
	"github.com/joho/godotenv"
)

// envInt reads a positive integer env var, exiting on malformed values.
func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		log.Fatalf("%s must be a positive integer, got %q", key, v)
	}
	return n
}

func main() {
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		log.Fatalf("load .env: %v", err)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dataDir := os.Getenv("DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}
	st, err := store.Open(dataDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()

	authSvc := auth.New(st, auth.Config{
		ClientID: os.Getenv("GITHUB_CLIENT_ID"),
		APIURL:   os.Getenv("GITHUB_API_URL"),
		OAuthURL: os.Getenv("GITHUB_OAUTH_URL"),
	})
	if os.Getenv("GITHUB_CLIENT_ID") == "" {
		log.Print("GITHUB_CLIENT_ID is unset: /v1/auth/* will return 503")
	}
	reg := api.NewWithConfig(st, authSvc.Authenticate, api.Config{
		MaxBundleBytes: int64(envInt("MAX_BUNDLE_BYTES", 5<<20)),
		PublishPerHour: envInt("PUBLISH_RATE_PER_HOUR", 30),
	})
	// The unauthenticated auth routes proxy to GitHub, so limit them per IP.
	// X-Forwarded-For is only honoured when TRUSTED_PROXY=true.
	authLim := api.NewLimiter(envInt("AUTH_RATE_PER_MINUTE", 30), time.Minute, nil)
	authH := api.LimitByIP(authLim, os.Getenv("TRUSTED_PROXY") == "true", authSvc.Handler())

	mux := http.NewServeMux()
	mux.Handle("/v1/auth/", authH)
	mux.Handle("/v1/", reg.Handler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		log.Println("Health check endpoint hit")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok"}`))
	})

	srv := &http.Server{Addr: ":" + port, Handler: mux}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errc := make(chan error, 1)
	go func() {
		log.Printf("listening on :%s", port)
		errc <- srv.ListenAndServe()
	}()

	select {
	case err := <-errc:
		log.Fatal(err)
	case <-ctx.Done():
		stop()
		log.Print("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("shutdown: %v", err)
	}
}
