package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
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

// parseTokenTTLDays parses TOKEN_TTL_DAYS: empty means 90, 0 means tokens
// never expire, anything negative, non-numeric or absurdly large is an error
// (the server refuses to start rather than guess about a security setting).
func parseTokenTTLDays(v string) (time.Duration, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 90 * 24 * time.Hour, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 36500 {
		return 0, fmt.Errorf("TOKEN_TTL_DAYS must be a whole number of days from 0 (never expires) to 36500, got %q", v)
	}
	return time.Duration(n) * 24 * time.Hour, nil
}

// parseReportRate parses REPORT_RATE_PER_HOUR: empty means 5, 0 switches
// reporting off (the route answers 404), anything else that is not a whole
// number from 0 to 100000 is an error.
func parseReportRate(v string) (int, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 5, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > 100000 {
		return 0, fmt.Errorf("REPORT_RATE_PER_HOUR must be a whole number from 0 (reporting off) to 100000, got %q", v)
	}
	return n, nil
}

// parseHTTPURL validates an optional http(s) URL env var. The error never
// repeats the value: a webhook URL usually embeds a secret.
func parseHTTPURL(key, v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return "", nil
	}
	u, err := url.Parse(v)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("%s must be an absolute http:// or https:// URL (value not shown)", key)
	}
	return v, nil
}

// parseQuotaLimits reads MAX_USER_BYTES, MAX_USER_BUNDLES, MAX_BUNDLE_VERSIONS
// and MAX_TOTAL_BYTES. Unset means the default, 0 disables a limit, and
// anything negative, non-numeric or too large is an error (the server
// refuses to start rather than silently run without a limit it was asked for).
func parseQuotaLimits(getenv func(string) string) (store.Limits, error) {
	l := store.DefaultLimits()
	for _, f := range []struct {
		key string
		dst *int64
	}{
		{"MAX_USER_BYTES", &l.UserBytes},
		{"MAX_USER_BUNDLES", &l.UserBundles},
		{"MAX_BUNDLE_VERSIONS", &l.BundleVersions},
		{"MAX_TOTAL_BYTES", &l.TotalBytes},
	} {
		v := strings.TrimSpace(getenv(f.key))
		if v == "" {
			continue
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return store.Limits{}, fmt.Errorf("%s must be a whole number of at least 0 (0 disables the limit), got %q", f.key, v)
		}
		*f.dst = n
	}
	return l, nil
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
	// Parse before opening the store: a bad limit must refuse to start before
	// the database is migrated.
	limits, err := parseQuotaLimits(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	st, err := store.Open(dataDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	defer st.Close()
	st.SetLimits(limits)
	log.Printf("quotas: user %d bytes, %d bundles, %d versions per bundle; registry %d bytes (0 = unlimited)",
		limits.UserBytes, limits.UserBundles, limits.BundleVersions, limits.TotalBytes)

	// Admins are GitHub numeric ids. A malformed list is fatal: silently
	// ignoring a typo in a security setting could lock out the real admin.
	admins, err := auth.ParseAdminIDs(os.Getenv("ADMIN_GITHUB_IDS"))
	if err != nil {
		log.Fatal(err)
	}
	if len(admins) == 0 {
		log.Print("ADMIN_GITHUB_IDS is unset: /v1/admin/* is disabled")
	}

	tokenTTL, err := parseTokenTTLDays(os.Getenv("TOKEN_TTL_DAYS"))
	if err != nil {
		log.Fatal(err)
	}
	if tokenTTL == 0 {
		log.Print("TOKEN_TTL_DAYS=0: new API tokens never expire")
	}
	// Housekeeping: forget tokens that expired or were revoked over 30 days ago.
	if n, err := st.PurgeTokens(); err != nil {
		log.Printf("purge old tokens: %v", err)
	} else if n > 0 {
		log.Printf("purged %d old token rows", n)
	}

	authSvc := auth.New(st, auth.Config{
		TokenTTL: tokenTTL,
		AdminIDs: admins,
		ClientID: os.Getenv("GITHUB_CLIENT_ID"),
		APIURL:   os.Getenv("GITHUB_API_URL"),
		OAuthURL: os.Getenv("GITHUB_OAUTH_URL"),
	})
	if os.Getenv("GITHUB_CLIENT_ID") == "" {
		log.Print("GITHUB_CLIENT_ID is unset: /v1/auth/* will return 503")
	}
	// Reports: parsed here so a bad value refuses to start. The webhook URL is
	// operator-supplied and may hold a secret, so only its host is logged.
	reportRate, err := parseReportRate(os.Getenv("REPORT_RATE_PER_HOUR"))
	if err != nil {
		log.Fatal(err)
	}
	webhookURL, err := parseHTTPURL("REPORT_WEBHOOK_URL", os.Getenv("REPORT_WEBHOOK_URL"))
	if err != nil {
		log.Fatal(err)
	}
	publicURL, err := parseHTTPURL("PUBLIC_URL", os.Getenv("PUBLIC_URL"))
	if err != nil {
		log.Fatal(err)
	}
	trustProxy, ipHeader := os.Getenv("TRUSTED_PROXY") == "true", os.Getenv("CLIENT_IP_HEADER")
	apiCfg := api.Config{
		MaxBundleBytes:  int64(envInt("MAX_BUNDLE_BYTES", 5<<20)),
		PublishPerHour:  envInt("PUBLISH_RATE_PER_HOUR", 30),
		IsAdmin:         authSvc.IsAdmin,
		TrustProxy:      trustProxy,
		ClientIPHeader:  ipHeader,
		ReportPerHour:   reportRate,
		ReportsDisabled: reportRate == 0,
	}
	var hook *api.Webhook
	switch {
	case reportRate == 0:
		log.Print("REPORT_RATE_PER_HOUR=0: reporting is switched off (the report route answers 404)")
	case webhookURL != "":
		hook = api.NewWebhook(api.WebhookConfig{URL: webhookURL, PublicURL: publicURL})
		apiCfg.Notifier = hook
		log.Printf("report notifications go to webhook host %s", hostOf(webhookURL))
	default:
		log.Print("REPORT_WEBHOOK_URL is unset: reports are stored and visible with `capm admin reports` only")
	}
	reg := api.NewWithConfig(st, authSvc.Authenticate, apiCfg)
	// The auth routes proxy to GitHub, so limit them per IP. The limiter wraps
	// the whole /v1/auth/ handler, so it also covers the authenticated token
	// routes (me, tokens, revoke); that is fine at CLI volumes.
	// X-Forwarded-For is only honoured when TRUSTED_PROXY=true; CLIENT_IP_HEADER
	// (e.g. CF-Connecting-IP) takes precedence when set and valid.
	authLim := api.NewLimiter(envInt("AUTH_RATE_PER_MINUTE", 30), time.Minute, nil)
	authH := api.LimitByIP(authLim, trustProxy, ipHeader, authSvc.Handler())

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
	if hook != nil {
		hook.Close(3 * time.Second) // drain queued notifications briefly, then abandon
	}
}

// hostOf is the host of a URL already validated by parseHTTPURL.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}
