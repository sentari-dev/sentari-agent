//go:build enterprise

package main

import (
	"testing"
	"time"
)

// TestDecideCertExpiryAction covers the pure cert-expiry recovery policy
// (finding offline-7): a valid cert means normal operation; an expired cert
// with an enrollment token available triggers automatic re-enrollment; an
// expired cert with no token triggers a loud, actionable error instead of a
// generic TLS failure loop.
func TestDecideCertExpiryAction(t *testing.T) {
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	valid := now.Add(30 * 24 * time.Hour)    // NotAfter in the future
	expired := now.Add(-1 * time.Hour)       // NotAfter in the past
	justExpired := now.Add(-1 * time.Second) // lapsed a moment ago

	cases := []struct {
		name      string
		notAfter  time.Time
		haveToken bool
		want      certExpiryDecision
	}{
		{"valid cert with token → normal", valid, true, certOK},
		{"valid cert no token → normal", valid, false, certOK},
		{"expired cert with token → re-enroll", expired, true, certReenroll},
		{"expired cert no token → loud error", expired, false, certExpiredNoToken},
		{"just-expired with token → re-enroll", justExpired, true, certReenroll},
		{"just-expired no token → loud error", justExpired, false, certExpiredNoToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decideCertExpiryAction(tc.notAfter, now, tc.haveToken); got != tc.want {
				t.Fatalf("decideCertExpiryAction(notAfter=%s, haveToken=%v) = %d, want %d",
					tc.notAfter, tc.haveToken, got, tc.want)
			}
		})
	}
}

// TestDecideCertExpiryActionBoundary confirms the boundary is strict: a cert
// whose NotAfter is exactly now is treated as expired (now.Before(notAfter) is
// false), so recovery engages rather than serving with a cert valid for zero
// more time.
func TestDecideCertExpiryActionBoundary(t *testing.T) {
	now := time.Now()
	if got := decideCertExpiryAction(now, now, true); got != certReenroll {
		t.Fatalf("NotAfter == now with token: want certReenroll, got %d", got)
	}
	if got := decideCertExpiryAction(now, now, false); got != certExpiredNoToken {
		t.Fatalf("NotAfter == now no token: want certExpiredNoToken, got %d", got)
	}
}
