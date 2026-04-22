package comms

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"strconv"
	"syscall"
	"time"

	"github.com/sentari-dev/sentari-agent/common/logging"
)

// RetryConfig controls the exponential-backoff retry loop.  The zero
// value is a reasonable default (5 attempts, base 500 ms, cap 60 s).
// Exposed so tests can shrink it.
type RetryConfig struct {
	MaxAttempts  int           // total attempts, including the first
	BaseDelay    time.Duration // first retry wait (before jitter)
	MaxDelay     time.Duration // cap for any single wait
	JitterFactor float64       // ±fraction, e.g. 0.1 = ±10%
}

// defaultRetryConfig is used when callers don't pass one.  The limits
// (5 attempts, 60 s cap) are tuned for the agent's once-per-hour scan
// cadence — longer than that and a stuck retry starts colliding with
// the next cycle.
var defaultRetryConfig = RetryConfig{
	MaxAttempts:  5,
	BaseDelay:    500 * time.Millisecond,
	MaxDelay:     60 * time.Second,
	JitterFactor: 0.1,
}

// isRetryable classifies an outbound-request error as worth retrying.
// We retry on transient network conditions (connection reset/refused,
// i/o timeout, DNS flakes the OS reports as temporary).  Any
// non-network error (4xx-class after parsing the body, protocol
// errors, URL parse failures, context cancellation) is NOT retryable
// and the caller handles it.
//
// HTTP status codes that warrant a retry (429, 5xx) are handled
// separately by ``retryableStatus`` — this helper is only for
// transport-layer errors returned from http.Client.Do.
func isRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	// Network-layer errors: timeouts, refused, reset, EOF mid-body.
	var ue *url.Error
	if errors.As(err, &ue) {
		if ue.Timeout() || ue.Temporary() {
			return true
		}
		// Connection refused / reset bubble up as syscall.Errno;
		// retry those — likely server restart or pod rollover.
		if errors.Is(err, syscall.ECONNREFUSED) ||
			errors.Is(err, syscall.ECONNRESET) ||
			errors.Is(err, io.ErrUnexpectedEOF) {
			return true
		}
	}
	return false
}

// retryableStatus returns true when the server response code warrants
// a retry.  429 (rate-limited) and 5xx (server transient) are safe to
// hit again; 4xx (client error) is our fault and retrying won't help.
func retryableStatus(code int) bool {
	return code == http.StatusTooManyRequests || code >= 500
}

// parseRetryAfter reads the Retry-After header in either of the two
// valid RFC 7231 forms (delta-seconds or HTTP-date).  Returns 0 when
// the header is absent or unparseable — the caller then falls back
// to the computed backoff.
func parseRetryAfter(h string) time.Duration {
	h = trimSpace(h)
	if h == "" {
		return 0
	}
	if secs, err := strconv.Atoi(h); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(h); err == nil {
		d := time.Until(t)
		if d > 0 {
			return d
		}
	}
	return 0
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// nextBackoff returns the wait before attempt n (1-indexed).  Classic
// exponential: base * 2^(n-1), capped, with ±jitter.
func nextBackoff(n int, cfg RetryConfig) time.Duration {
	if n <= 0 {
		return 0
	}
	d := cfg.BaseDelay
	for i := 1; i < n; i++ {
		d *= 2
		if d > cfg.MaxDelay {
			d = cfg.MaxDelay
			break
		}
	}
	if cfg.JitterFactor > 0 {
		d = applyJitter(d, cfg.JitterFactor)
	}
	if d > cfg.MaxDelay {
		d = cfg.MaxDelay
	}
	return d
}

// applyJitter returns d ± (d*factor), using crypto/rand so the
// stagger across a fleet of agents is unpredictable to network
// observers.  math/rand's default seed would let an attacker who
// scraped one agent's timings predict the rest.
func applyJitter(d time.Duration, factor float64) time.Duration {
	window := int64(float64(d) * factor)
	if window <= 0 {
		return d
	}
	n, err := rand.Int(rand.Reader, big.NewInt(window*2))
	if err != nil {
		return d
	}
	return d + time.Duration(n.Int64()-window)
}

// doRequest issues req through c.httpClient with retry/backoff on
// transport errors, 429, and 5xx.  The caller provides a ``reqBuilder``
// — a factory that returns a *fresh* *http.Request* on every attempt
// — because http.Request.Body is a one-shot io.Reader and reusing it
// silently posts an empty body on the retry.
//
// Returns the final *http.Response (which the caller must Close) and
// nil on success, or nil and an error describing the last failure.
// The caller is responsible for reading + classifying the status
// code on success; ``doRequest`` only peeks to decide whether to
// retry.
func (c *Client) doRequest(
	ctx context.Context,
	op string, // human label for logs, e.g. "upload_scan"
	reqBuilder func(ctx context.Context) (*http.Request, error),
) (*http.Response, error) {
	cfg := defaultRetryConfig
	if c.retry != nil {
		cfg = *c.retry
	}

	log := logging.LoggerFromContext(ctx)

	var lastErr error
	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		req, err := reqBuilder(ctx)
		if err != nil {
			// Non-retryable: building the request itself failed.
			return nil, fmt.Errorf("%s: build request: %w", op, err)
		}
		attachRequestID(req, ctx)

		resp, err := c.httpClient.Do(req)
		if err == nil && !retryableStatus(resp.StatusCode) {
			return resp, nil
		}

		// Capture context for backoff or final error.
		var waitHint time.Duration
		if resp != nil {
			waitHint = parseRetryAfter(resp.Header.Get("Retry-After"))
			// Drain fully (not just the first 512 B) so the keep-alive
			// connection can be reused on the retry.  The server
			// caps the response at maxResponseSize, so unbounded
			// io.Copy is bounded in practice.
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		// http.Client.Do can return non-nil resp AND non-nil err
		// (e.g. a CheckRedirect violation).  Combine both into
		// lastErr so the final "giving up" error reflects the real
		// cause, and base the retryability decision on the err.
		switch {
		case err != nil && resp != nil:
			lastErr = fmt.Errorf("%s: %w (HTTP %d)", op, err, resp.StatusCode)
			if !isRetryable(err) {
				return nil, lastErr
			}
		case err != nil:
			lastErr = fmt.Errorf("%s: %w", op, err)
			if !isRetryable(err) {
				return nil, lastErr
			}
		default: // err == nil, resp != nil with retryable status
			lastErr = fmt.Errorf("%s: HTTP %d", op, resp.StatusCode)
			if !retryableStatus(resp.StatusCode) {
				return nil, lastErr
			}
		}

		if attempt == cfg.MaxAttempts {
			break
		}

		wait := waitHint
		if wait <= 0 {
			wait = nextBackoff(attempt, cfg)
		}
		log.Warn(
			"outbound request retrying",
			slog.String("op", op),
			slog.Int("attempt", attempt),
			slog.Duration("wait", wait),
			slog.String("cause", lastErr.Error()),
		)
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%s: %w", op, ctx.Err())
		case <-time.After(wait):
		}
	}

	return nil, fmt.Errorf("%s: giving up after %d attempts: %w", op, cfg.MaxAttempts, lastErr)
}

// attachRequestID stamps X-Request-ID on req when the context carries
// one.  Missing IDs stay missing; the server mints a fresh one in
// that case (see server/main.py RequestIDMiddleware).
func attachRequestID(req *http.Request, ctx context.Context) {
	id := logging.RequestIDFromContext(ctx)
	if id == "" {
		return
	}
	req.Header.Set("X-Request-ID", id)
}
