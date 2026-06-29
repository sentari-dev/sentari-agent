package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestWithRequestID_RoundTrip(t *testing.T) {
	// The simplest possible guard: the contextvar round-trips
	// exactly.  If this breaks, every downstream assumption does.
	ctx := WithRequestID(context.Background(), "scan-abc")
	if got := RequestIDFromContext(ctx); got != "scan-abc" {
		t.Fatalf("round trip: got %q want %q", got, "scan-abc")
	}
	if got := RequestIDFromContext(context.Background()); got != "" {
		t.Fatalf("unbound context should return empty, got %q", got)
	}
}

func TestNewRequestID_PrefixAndLength(t *testing.T) {
	// Every ID starts with "scan-" (operators need to recognise them
	// in logs) and has enough entropy to avoid collision across a
	// daily fleet scan.  16 bytes hex = 32 chars + 5-char prefix.
	id := NewRequestID()
	if !strings.HasPrefix(id, "scan-") {
		t.Fatalf("expected scan- prefix, got %q", id)
	}
	if len(id) != 5+32 {
		t.Fatalf("expected 37-char ID, got %d: %q", len(id), id)
	}
	// Two calls must differ — otherwise all cycles would collide.
	if NewRequestID() == id {
		t.Fatal("NewRequestID returned two identical IDs; entropy source broken")
	}
}

func TestLoggerFromContext_EmitsRequestIDField(t *testing.T) {
	// Capture JSON lines to assert the processor attaches request_id
	// when the contextvar is set.  This is the shape the server-side
	// log pipeline joins on.
	buf := &bytes.Buffer{}
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, nil)))
	ctx := WithRequestID(context.Background(), "scan-xyz")
	LoggerFromContext(ctx).Info("something happened")

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("decode log line: %v", err)
	}
	if rec["request_id"] != "scan-xyz" {
		t.Fatalf("expected request_id=scan-xyz, got %v", rec["request_id"])
	}
}

func TestLoggerFromContext_NoRequestIDWhenUnbound(t *testing.T) {
	// When no ID is bound, we want the logger to NOT add the field —
	// agent startup and flag parsing happen before any cycle exists,
	// and a spurious request_id="" there would just be noise.
	buf := &bytes.Buffer{}
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, nil)))
	LoggerFromContext(context.Background()).Info("startup line")

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("decode log line: %v", err)
	}
	if _, present := rec["request_id"]; present {
		t.Fatalf("expected request_id absent when unbound, got %v", rec["request_id"])
	}
}
