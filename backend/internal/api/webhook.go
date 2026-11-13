package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ReportEvent is a newly stored report, as handed to a ReportNotifier.
type ReportEvent struct {
	ID                                    int64
	Owner, Name, Version, Reason, Details string
}

// ReportNotifier is told about each newly stored report. Implementations must
// not block.
type ReportNotifier interface{ Notify(ReportEvent) }

const (
	webhookTimeout   = 5 * time.Second
	webhookQueueSize = 32
	// webhookDetailsMax is the length of the truncated details field.
	webhookDetailsMax = 200
)

// WebhookConfig configures NewWebhook.
//
// URL is operator-supplied (REPORT_WEBHOOK_URL), never derived from any
// request, so there is no user-controlled destination (no SSRF surface); the
// only user-influenced data sent is in the body. Redirects are not followed.
type WebhookConfig struct {
	URL       string
	PublicURL string        // used only for the "url" link; "" omits it
	Timeout   time.Duration // default 5s
	QueueSize int           // default 32
}

// Webhook posts one JSON message per report from a small bounded queue, in
// one background goroutine: asynchronous (never blocks or fails a request),
// 5s timeout, no retries, full queue drops with a WARN. The URL is never
// logged in full (it may embed a secret): only its host.
type Webhook struct {
	cfg     WebhookConfig
	host    string
	hc      *http.Client
	q       chan ReportEvent
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	mu      sync.RWMutex
	closed  bool
	dropped atomic.Int64
}

func NewWebhook(cfg WebhookConfig) *Webhook {
	if cfg.Timeout <= 0 {
		cfg.Timeout = webhookTimeout
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = webhookQueueSize
	}
	w := &Webhook{cfg: cfg, host: hostOnly(cfg.URL), q: make(chan ReportEvent, cfg.QueueSize), done: make(chan struct{})}
	w.ctx, w.cancel = context.WithCancel(context.Background())
	w.hc = &http.Client{Timeout: cfg.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	go w.run()
	return w
}

// hostOnly is the host[:port] of a URL, for logs; "" if unparsable.
func hostOnly(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// Dropped is how many notifications were dropped because the queue was full.
func (w *Webhook) Dropped() int64 { return w.dropped.Load() }

func (w *Webhook) Notify(ev ReportEvent) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return
	}
	select {
	case w.q <- ev:
	default:
		w.dropped.Add(1)
		log.Printf("WARN: report webhook queue full; dropping a notification (host %s)", w.host)
	}
}

// Close stops accepting events, lets queued ones finish for up to grace, then
// abandons whatever is left (cancelling a request in flight). Idempotent.
func (w *Webhook) Close(grace time.Duration) {
	w.mu.Lock()
	if !w.closed {
		w.closed = true
		close(w.q)
	}
	w.mu.Unlock()
	select {
	case <-w.done:
	case <-time.After(grace):
		w.cancel()
		<-w.done
	}
}

func (w *Webhook) run() {
	defer close(w.done)
	for ev := range w.q {
		if w.ctx.Err() != nil {
			continue
		}
		w.send(ev)
	}
}

func oneLine(s string, max int) string {
	s = cleanDetails(s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		s = string(r[:max]) + "…"
	}
	return s
}

func (w *Webhook) payload(ev ReportEvent) []byte {
	bundle := ev.Owner + "/" + ev.Name
	text := "New capm report (" + ev.Reason + "): " + bundle
	if ev.Version != "" {
		text += "@" + ev.Version
	}
	p := map[string]any{
		"text": text, "bundle": bundle, "version": ev.Version, "reason": ev.Reason,
		"reportId": ev.ID, "details": oneLine(ev.Details, webhookDetailsMax),
	}
	if base := strings.TrimRight(w.cfg.PublicURL, "/"); base != "" {
		p["url"] = base + "/bundles/" + url.PathEscape(ev.Owner) + "/" + url.PathEscape(ev.Name)
	}
	b, _ := json.Marshal(p)
	return b
}

func (w *Webhook) send(ev ReportEvent) {
	req, err := http.NewRequestWithContext(w.ctx, "POST", w.cfg.URL, bytes.NewReader(w.payload(ev)))
	if err != nil {
		log.Printf("WARN: report webhook: bad request for host %s", w.host)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "capm-registry")
	resp, err := w.hc.Do(req)
	if err != nil {
		// url.Error embeds the full URL; log only its cause.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		log.Printf("WARN: report webhook to %s failed: %v", w.host, err)
		return
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("WARN: report webhook to %s answered %d", w.host, resp.StatusCode)
	}
}
