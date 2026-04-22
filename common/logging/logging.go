// Package logging configures structured logs for the agent and provides a
// request-ID helper that the comms client stamps onto every outbound
// request.  Without this the agent's 56-odd log sites emit plain stderr
// lines that can't be joined to the server's structured log stream —
// customers chasing a "my scan uploaded but never appeared" bug end up
// grepping unrelated timestamps across two log formats.
//
// The request_id that flows end-to-end is:
//
//   agent scan cycle ──► X-Request-ID header ──► FastAPI middleware
//                                              ──► Celery task header
//                                              ──► worker logs
//
// Every cycle mints a fresh UUID-ish string; every log line emitted in
// that cycle carries it as ``request_id`` via ``LoggerFromContext``.
package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"strings"
)

type ctxKey struct{}

var requestIDKey = ctxKey{}

// Configure installs a slog handler on the default logger.  JSON is the
// default so log shippers / SIEMs don't need a bespoke parser; set
// SENTARI_AGENT_LOG_FORMAT=text for interactive dev.  Idempotent — safe
// to call multiple times.
func Configure() {
	ConfigureTo(os.Stderr)
}

// ConfigureTo routes slog output to w.  Exposed for tests that want to
// capture the JSON lines without forking a subprocess.
func ConfigureTo(w io.Writer) {
	level := parseLevel(os.Getenv("SENTARI_AGENT_LOG_LEVEL"))
	opts := &slog.HandlerOptions{Level: level}

	var handler slog.Handler
	switch strings.ToLower(os.Getenv("SENTARI_AGENT_LOG_FORMAT")) {
	case "text":
		handler = slog.NewTextHandler(w, opts)
	default:
		// JSON by default.  The server side picks JSON based on
		// "is stderr a TTY?"; the agent runs as a daemon on every
		// box so treating stderr-is-a-pipe as the default is right.
		handler = slog.NewJSONHandler(w, opts)
	}
	slog.SetDefault(slog.New(handler))
}

func parseLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// WithRequestID returns a copy of ctx carrying id as the request_id.
// Generate one per scan cycle (in main_enterprise.go) so API, server,
// and worker logs can be joined by a single ``grep <id>``.
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestIDFromContext returns the bound request_id, or "" if none.
// The comms client reads this in every outbound request builder and
// attaches it as ``X-Request-ID``.
func RequestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// NewRequestID mints a fresh 16-byte hex ID prefixed with ``scan-`` so
// it's obvious in logs where the ID originated.  crypto/rand for
// unpredictability — these IDs go into headers, and predictable IDs
// invite attackers to inject their own trace annotations.
func NewRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to an obvious placeholder rather than panic —
		// the agent must never die because entropy stalled.
		return "scan-nondistinct"
	}
	return "scan-" + hex.EncodeToString(b[:])
}

// LoggerFromContext returns the default logger with ``request_id``
// pre-bound when ctx carries one.  Callers should prefer this over
// ``slog.Default()`` directly so every line they emit joins the
// correlation chain automatically.
func LoggerFromContext(ctx context.Context) *slog.Logger {
	id := RequestIDFromContext(ctx)
	if id == "" {
		return slog.Default()
	}
	return slog.Default().With("request_id", id)
}
