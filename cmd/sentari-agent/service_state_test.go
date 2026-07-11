//go:build enterprise

package main

import (
	"testing"
)

// TestServiceControlLoopStopCancelsAndReportsStopPending verifies the core SCM
// contract: a Stop request must report StopPending, cancel the shared serve-loop
// context, and return — in that order (StopPending before cancel, so the SCM
// sees the pending state before teardown work begins).
func TestServiceControlLoopStopCancelsAndReportsStopPending(t *testing.T) {
	reqs := make(chan svcControlCmd, 1)

	var order []string
	cancelled := false
	stopPending := false

	reportRunning := func() { order = append(order, "running") }
	reportStopPending := func() {
		order = append(order, "stop_pending")
		stopPending = true
	}
	cancel := func() {
		order = append(order, "cancel")
		cancelled = true
	}

	reqs <- svcCmdStop
	close(reqs)

	serviceControlLoop(reqs, reportRunning, reportStopPending, cancel)

	if !stopPending {
		t.Fatal("expected StopPending to be reported on Stop")
	}
	if !cancelled {
		t.Fatal("expected cancel() to be invoked on Stop")
	}
	if len(order) != 2 || order[0] != "stop_pending" || order[1] != "cancel" {
		t.Fatalf("expected [stop_pending cancel] in order, got %v", order)
	}
}

// TestServiceControlLoopInterrogateEchoesRunning verifies that an Interrogate
// request re-reports Running (the SCM status echo) and keeps the loop alive,
// and that a subsequent Stop still tears down cleanly.
func TestServiceControlLoopInterrogateEchoesRunning(t *testing.T) {
	reqs := make(chan svcControlCmd, 2)

	runningReports := 0
	cancelled := false
	stopPending := false

	reportRunning := func() { runningReports++ }
	reportStopPending := func() { stopPending = true }
	cancel := func() { cancelled = true }

	reqs <- svcCmdInterrogate
	reqs <- svcCmdStop
	close(reqs)

	serviceControlLoop(reqs, reportRunning, reportStopPending, cancel)

	if runningReports != 1 {
		t.Fatalf("expected exactly 1 Running echo on Interrogate, got %d", runningReports)
	}
	if !stopPending {
		t.Fatal("expected StopPending after the trailing Stop")
	}
	if !cancelled {
		t.Fatal("expected cancel() after the trailing Stop")
	}
}

// TestServiceControlLoopClosedChannelReturnsWithoutCancel verifies that if the
// request channel closes without a Stop (an abnormal SCM teardown), the loop
// returns without spuriously cancelling — the deferred cancel in the caller
// owns cleanup in that case.
func TestServiceControlLoopClosedChannelReturnsWithoutCancel(t *testing.T) {
	reqs := make(chan svcControlCmd)
	close(reqs)

	cancelled := false
	stopPending := false

	serviceControlLoop(reqs,
		func() {},
		func() { stopPending = true },
		func() { cancelled = true },
	)

	if cancelled {
		t.Fatal("did not expect cancel() when the channel closes without a Stop")
	}
	if stopPending {
		t.Fatal("did not expect StopPending when the channel closes without a Stop")
	}
}
