package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MasonD-007/capm/backend/internal/api"
	"github.com/MasonD-007/capm/backend/internal/auth"
	"github.com/MasonD-007/capm/backend/internal/store"
	"github.com/joho/godotenv"
)

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
	reg := api.New(st, authSvc.Authenticate)

	mux := http.NewServeMux()
	mux.Handle("/v1/auth/", authSvc.Handler())
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
