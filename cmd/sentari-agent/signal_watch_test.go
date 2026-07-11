//go:build enterprise

package main

import (
	"context"
	"os"
	"syscall"
	"testing"
	"time"
)

// TestWatchSignals_FirstSignalGracefulSecondForces asserts the two-stage
// termination contract (finding concurrency-1):
//   - the FIRST signal is forwarded on gotSignal (for the shutdown audit entry)
//     and cancels the root context (graceful path), WITHOUT calling exit; and
//   - a SECOND signal delivered while the graceful path is still unwinding
//     forces a hard exit(1) so a wedged shutdown can never swallow the
//     operator's force-quit.
func TestWatchSignals_FirstSignalGracefulSecondForces(t *testing.T) {
	sigCh := make(chan os.Signal, 2)
	gotSignal := make(chan os.Signal, 1)
	_, cancel := context.WithCancel(context.Background())
	cancelled := make(chan struct{})
	wrappedCancel := context.CancelFunc(func() {
		cancel()
		close(cancelled)
	})

	exitCode := make(chan int, 1)
	exit := func(code int) { exitCode <- code }

	done := make(chan struct{})
	go func() {
		watchSignals(sigCh, gotSignal, wrappedCancel, exit, nil)
		close(done)
	}()

	// First signal: graceful.
	sigCh <- syscall.SIGTERM
	select {
	case s := <-gotSignal:
		if s != syscall.SIGTERM {
			t.Fatalf("forwarded signal = %v, want SIGTERM", s)
		}
	case <-time.After(time.Second):
		t.Fatal("first signal was not forwarded on gotSignal")
	}
	select {
	case <-cancelled:
	case <-time.After(time.Second):
		t.Fatal("cancel() not invoked on first signal")
	}
	// No exit yet on the graceful path.
	select {
	case code := <-exitCode:
		t.Fatalf("exit(%d) called on first (graceful) signal; want none", code)
	default:
	}

	// Second signal: hard exit.
	sigCh <- syscall.SIGINT
	select {
	case code := <-exitCode:
		if code != 1 {
			t.Fatalf("forced-exit code = %d, want 1", code)
		}
	case <-time.After(time.Second):
		t.Fatal("second signal did not force exit(1)")
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchSignals did not return after forced exit")
	}
}

// TestWatchSignals_ChannelClosedNoExit asserts watchSignals returns cleanly if
// the signal channel is closed (deferred signal.Stop path at runServe return)
// without forcing an exit — a closed channel must not read as a phantom second
// signal.
func TestWatchSignals_ChannelClosedNoExit(t *testing.T) {
	sigCh := make(chan os.Signal, 1)
	gotSignal := make(chan os.Signal, 1)
	cancelled := make(chan struct{})
	cancel := context.CancelFunc(func() { close(cancelled) })
	exitCalled := make(chan int, 1)
	exit := func(code int) { exitCalled <- code }

	done := make(chan struct{})
	go func() {
		watchSignals(sigCh, gotSignal, cancel, exit, nil)
		close(done)
	}()

	sigCh <- syscall.SIGTERM
	<-gotSignal
	<-cancelled

	// Close the channel instead of sending a second signal.
	close(sigCh)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("watchSignals did not return after channel close")
	}
	select {
	case code := <-exitCalled:
		t.Fatalf("exit(%d) called on channel close; want none", code)
	default:
	}
}
