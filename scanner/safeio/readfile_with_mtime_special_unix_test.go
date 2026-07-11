//go:build unix

package safeio

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestReadFileWithMTime_FIFORefused: a FIFO with no writer blocks
// forever on a blocking open().  ReadFileWithMTime must refuse it
// promptly with ErrNotRegular and must NOT hang — a package shipping
// its manifest as a FIFO would otherwise be a fleet-wide scanner-hang
// DoS.  This exercises the non-regular-file guard added when the
// helper was consolidated into safeio.
func TestReadFileWithMTime_FIFORefused(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "mcp.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create FIFO on this platform: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, _, err := ReadFileWithMTime(fifo, 1024)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error reading a FIFO, got nil")
		}
		if !errors.Is(err, ErrNotRegular) {
			t.Errorf("expected ErrNotRegular, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ReadFileWithMTime hung on a FIFO with no writer (DoS); expected prompt ErrNotRegular")
	}
}
