package comms

import (
	"testing"
	"time"
)

// TestNextBackoff_DefaultJitterPathStaysInBounds drives the PRODUCTION
// default backoff schedule — defaultRetryConfig, JitterFactor 0.1 — through
// nextBackoff.  The rest of the suite injects JitterFactor: 0 for
// determinism, so the crypto/rand jitter branch (applyJitter, taken only
// when cfg.JitterFactor > 0) was otherwise never exercised.
//
// For each attempt it recomputes the un-jittered exponential baseline the
// same way nextBackoff does (base * 2^(n-1), capped at MaxDelay) and asserts
// every sampled backoff lands within [baseline-window, baseline+window),
// re-capped at MaxDelay, where window = baseline * JitterFactor.  It also
// asserts the jitter actually varies the value across samples, proving the
// default path is genuinely taken and not silently returning the bare
// baseline.
func TestNextBackoff_DefaultJitterPathStaysInBounds(t *testing.T) {
	cfg := defaultRetryConfig // real production defaults; JitterFactor 0.1
	if cfg.JitterFactor <= 0 {
		t.Fatalf("expected the production default to enable jitter, got JitterFactor=%v", cfg.JitterFactor)
	}

	const samples = 300
	// Iterate past the point the schedule saturates at MaxDelay (attempt 8:
	// 500ms * 2^7 = 64s -> capped to 60s) so the capped-baseline jitter case
	// is covered too.
	for attempt := 1; attempt <= 9; attempt++ {
		// Recompute the capped exponential baseline exactly as nextBackoff does.
		baseline := cfg.BaseDelay
		for i := 1; i < attempt; i++ {
			baseline *= 2
			if baseline > cfg.MaxDelay {
				baseline = cfg.MaxDelay
				break
			}
		}
		window := time.Duration(float64(baseline) * cfg.JitterFactor)

		lower := baseline - window
		upper := baseline + window // applyJitter returns strictly < baseline+window
		if upper > cfg.MaxDelay {
			upper = cfg.MaxDelay
		}

		seen := make(map[time.Duration]struct{}, samples)
		for s := 0; s < samples; s++ {
			got := nextBackoff(attempt, cfg)
			if got < lower {
				t.Fatalf("attempt %d: backoff %v below lower bound %v (baseline %v, window %v)",
					attempt, got, lower, baseline, window)
			}
			if got > upper {
				t.Fatalf("attempt %d: backoff %v above upper bound %v (baseline %v, window %v)",
					attempt, got, upper, baseline, window)
			}
			if got > cfg.MaxDelay {
				t.Fatalf("attempt %d: backoff %v exceeds MaxDelay %v", attempt, got, cfg.MaxDelay)
			}
			seen[got] = struct{}{}
		}

		// window > 0 for every attempt here, so jitter must produce more than
		// one distinct value across the samples — otherwise the default jitter
		// branch was not actually taken.
		if window > 0 && len(seen) < 2 {
			t.Fatalf("attempt %d: expected jitter to vary the backoff across %d samples, got a single value",
				attempt, samples)
		}
	}
}
