//go:build enterprise

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestCryptoJitter_WithinBounds asserts the sleep jitter always lands within
// ±interval/10 so the ±10% thundering-herd spread is honoured, and that a
// sub-10ns interval (window rounds to 0) degrades to no jitter rather than
// panicking in rand.Int with a non-positive bound.
func TestCryptoJitter_WithinBounds(t *testing.T) {
	const interval = 3600 * time.Second
	window := interval / 10
	for i := 0; i < 2000; i++ {
		j := cryptoJitter(interval)
		if j < -window || j > window {
			t.Fatalf("cryptoJitter(%s) = %s, out of ±%s bound", interval, j, window)
		}
	}

	// window <= 0 → deterministic zero (no rand.Int call with a bad bound).
	if j := cryptoJitter(5 * time.Nanosecond); j != 0 {
		t.Fatalf("cryptoJitter(5ns) = %s, want 0 (window rounds to 0)", j)
	}
	if j := cryptoJitter(0); j != 0 {
		t.Fatalf("cryptoJitter(0) = %s, want 0", j)
	}
}

// TestIsScanRootDenied delegates to scanRootDeniedForOS(cleaned, runtime.GOOS);
// this covers the delegation with an OS-appropriate denied/allowed pair so the
// server can never point the agent at a sensitive system tree.
func TestIsScanRootDenied(t *testing.T) {
	var denied, allowed string
	if runtime.GOOS == "windows" {
		denied = `C:\Windows\System32`
		allowed = `C:\Users\alice\project`
	} else {
		denied = "/etc/ssh"
		allowed = "/opt/app"
	}
	if !isScanRootDenied(denied) {
		t.Fatalf("isScanRootDenied(%q) = false, want true on %s", denied, runtime.GOOS)
	}
	if isScanRootDenied(allowed) {
		t.Fatalf("isScanRootDenied(%q) = true, want false on %s", allowed, runtime.GOOS)
	}
}

// TestNotAfterOrZero covers both branches of the best-effort cert-NotAfter
// re-read used only for logging: a readable cert yields its real NotAfter; an
// unreadable path yields the zero time (never affects control flow).
func TestNotAfterOrZero(t *testing.T) {
	// Unreadable path → zero time.
	if got := notAfterOrZero(filepath.Join(t.TempDir(), "nope.crt")); !got.IsZero() {
		t.Fatalf("notAfterOrZero(missing) = %v, want zero time", got)
	}

	// Readable cert → its actual NotAfter.
	_, caKey, caCert := testCA(t)
	want := time.Now().Add(120 * 24 * time.Hour)
	certPEM, _ := issueDeviceCert(t, caKey, caCert, want)
	certFile := filepath.Join(t.TempDir(), "device.crt")
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	got := notAfterOrZero(certFile)
	if got.IsZero() {
		t.Fatal("notAfterOrZero(valid cert) returned zero time")
	}
	// x509 NotAfter is truncated to whole seconds; compare at that resolution.
	if !got.Truncate(time.Second).Equal(want.UTC().Truncate(time.Second)) {
		// DeviceCertNotAfterAt may return UTC; compare the instant, not the zone.
		if diff := got.Sub(want); diff > time.Second || diff < -time.Second {
			t.Fatalf("notAfterOrZero = %v, want ~%v (diff %v)", got, want, diff)
		}
	}
}
