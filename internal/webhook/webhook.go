// Package webhook fires the optional on_change notification (e.g.
// ntfy/Telegram) whenever state changes. It never blocks the caller and
// never fails loudly: a broken webhook must not break hodor.
package webhook

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// queueSize bounds the pending-notification queue: a single slow/stuck
// webhook endpoint must not let unbounded goroutines/memory pile up.
// Once full, new notifications are dropped (and logged) rather than
// blocking the caller (state.Store, holding its mutex).
const queueSize = 32

// Notifier returns a state.OnChangeFunc-compatible function that POSTs a
// small JSON body to url from a single background worker fed by a
// bounded queue. If url is empty, the returned function is a no-op.
func Notifier(url string, logger *slog.Logger) func(msg string) {
	if url == "" {
		return func(string) {}
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
		// on_change points at a user-controlled URL (config.go
		// validates scheme+host but not what's behind it); don't
		// follow redirects, which could otherwise be used to retarget
		// the POST (and its JSON body) at an internal/unexpected
		// endpoint.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	queue := make(chan string, queueSize)

	go func() {
		for msg := range queue {
			send(client, url, msg, logger)
		}
	}()

	return func(msg string) {
		select {
		case queue <- msg:
		default:
			if logger != nil {
				logger.Warn("on_change webhook queue full, dropping notification", "event", msg)
			}
		}
	}
}

func send(client *http.Client, url, msg string, logger *slog.Logger) {
	body, err := json.Marshal(map[string]any{
		"event": msg,
		"time":  time.Now().UTC(),
	})
	if err != nil {
		return
	}
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		if logger != nil {
			logger.Warn("on_change webhook failed", "err", err)
		}
		return
	}
	_, _ = io.Copy(io.Discard, resp.Body) // drain before Close, keeps the connection reusable
	_ = resp.Body.Close()
}
