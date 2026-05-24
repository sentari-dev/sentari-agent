//go:build unix

package scanner

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// Finding 2 — LoadVerifiedOverlayFromFile must NOT pull the whole file
// into memory before the size cap is enforced.  The current code calls
// os.ReadFile (unbounded) up front; a hostile cache file that is a FIFO
// with no writer hangs the agent forever (and a multi-GiB regular file
// OOMs it) before VerifyMapEnvelope's len() check ever runs.
//
// The safeio-routed fix refuses a non-regular file immediately, so the
// FIFO case returns (false) promptly.  RED: os.ReadFile hangs and the
// 3s timeout fires.  GREEN: prompt false.
func TestLoadVerifiedOverlay_RefusesFIFOWithoutHanging(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "license_map.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create FIFO on this platform: %v", err)
	}

	done := make(chan bool, 1)
	go func() {
		done <- LoadVerifiedOverlayFromFile(fifo)
	}()

	select {
	case ok := <-done:
		if ok {
			t.Fatal("expected FIFO cache file to be rejected (false), got true")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("LoadVerifiedOverlayFromFile hung on a FIFO (unbounded os.ReadFile); expected prompt false")
	}
}
