//go:build unix

package safeio

import (
	"errors"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestReadFile_DeviceRefused: a character device (/dev/null) is not a
// regular file.  Reading it must be refused with ErrNotRegular rather
// than silently returning its (empty) contents — a malicious package
// could ship a metadata file as a device node.
func TestReadFile_DeviceRefused(t *testing.T) {
	got, err := ReadFile("/dev/null", 1024)
	if err == nil {
		t.Fatalf("expected error reading a device node, got nil (data=%q)", got)
	}
	if !errors.Is(err, ErrNotRegular) {
		t.Errorf("expected ErrNotRegular, got %v", err)
	}
}

// TestReadFile_FIFORefused: a FIFO (named pipe) with no writer blocks
// forever on a blocking open().  ReadFile must refuse it promptly with
// ErrNotRegular and must NOT hang — otherwise a package shipping its
// METADATA as a FIFO is a fleet-wide scanner-hang DoS.
func TestReadFile_FIFORefused(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "METADATA")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create FIFO on this platform: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := ReadFile(fifo, 1024)
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
		t.Fatal("ReadFile hung on a FIFO with no writer (DoS); expected prompt ErrNotRegular")
	}
}

// TestOpen_FIFORefused: the streaming Open path (used by dpkg status,
// pyvenv.cfg readers) must also refuse a FIFO without hanging.
func TestOpen_FIFORefused(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "status")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("cannot create FIFO on this platform: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		f, err := Open(fifo)
		if f != nil {
			f.Close()
		}
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected error opening a FIFO, got nil")
		}
		if !errors.Is(err, ErrNotRegular) {
			t.Errorf("expected ErrNotRegular, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Open hung on a FIFO with no writer (DoS); expected prompt ErrNotRegular")
	}
}
