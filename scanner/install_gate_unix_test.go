//go:build unix

package scanner

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// TestInstallGateCache_RefusesFIFOWithoutHanging: a hostile / corrupt
// cache path that is a FIFO with no writer would hang an unbounded
// os.Open+io.ReadAll forever — a fleet-wide agent-hang DoS.  The
// safeio-backed loader must refuse it promptly with ErrNotRegular
// instead of blocking.
func TestInstallGateCache_RefusesFIFOWithoutHanging(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "policy_map.json")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create FIFO on this platform: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, _, err := LoadVerifiedInstallGateFromFile(fifo)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error loading a FIFO cache path, got nil")
		}
		if !errors.Is(err, safeio.ErrNotRegular) {
			t.Errorf("expected ErrNotRegular, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("LoadVerifiedInstallGateFromFile hung on a writer-less FIFO (DoS); expected prompt ErrNotRegular")
	}
}
