//go:build windows && enterprise

package main

import (
	"context"
	"fmt"

	"golang.org/x/sys/windows/svc"
)

// runServeUnderService runs the daemon under the Windows Service Control
// Manager when the process was started by the SCM (`sc start`, auto-start, or
// failure-recovery restart).  It answers the SCM's status callbacks —
// StartPending → Running → StopPending → Stopped — which the SCM requires
// within its timeout; a raw exe that never calls the dispatcher is killed with
// error 1053 and crash-loops.  install.ps1 registers this binary with
// `--serve`, so the SCM launches exactly this path.
//
// serve is the shared serveLoop closure.  It runs to completion when the root
// context is cancelled, which happens on a Stop / Shutdown control request —
// the same graceful teardown SIGINT/SIGTERM triggers on the console path.
//
// Returns ran=true when it dispatched under the SCM (the caller must then
// return without falling through to the console signal path), or ran=false
// when the process is NOT running as a service (e.g. launched from a console
// window for debugging) so the caller runs the ordinary console path.
func runServeUnderService(serve func(ctx context.Context, shutdownReason func() string)) (ran bool, err error) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		return false, fmt.Errorf("determine Windows service context: %w", err)
	}
	if !isService {
		// Console / interactive launch — let the caller take the normal
		// SIGINT/SIGTERM-driven path unchanged.
		return false, nil
	}
	if err := svc.Run(serviceName, &serveService{serve: serve}); err != nil {
		return true, fmt.Errorf("service dispatcher: %w", err)
	}
	return true, nil
}

// serveService adapts the shared serve loop to the svc.Handler interface.
type serveService struct {
	serve func(ctx context.Context, shutdownReason func() string)
}

// Execute is invoked by the SCM dispatcher on the service's main thread.  It
// reports the service through its state machine, runs the serve loop in a
// goroutine, and translates SCM control requests into the OS-agnostic
// serviceControlLoop that cancels the loop's root context.
func (s *serveService) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	// The serve loop shares its root context with the SCM control loop: a Stop
	// request cancels it, mirroring the SIGTERM cancellation on POSIX.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	served := make(chan struct{})
	go func() {
		defer close(served)
		s.serve(ctx, func() string { return "windows-service-stop" })
	}()

	changes <- svc.Status{State: svc.Running, Accepts: accepted}

	// Adapt SCM change requests — and the serve loop exiting on its own (a
	// fatal daemon error) — into the OS-agnostic command channel consumed by
	// serviceControlLoop.  Interrogate is echoed; Stop/Shutdown (and a
	// self-terminating serve loop) request teardown.
	cmds := make(chan svcControlCmd)
	go func() {
		defer close(cmds)
		for {
			select {
			case cr := <-r:
				switch cr.Cmd {
				case svc.Interrogate:
					cmds <- svcCmdInterrogate
				case svc.Stop, svc.Shutdown:
					cmds <- svcCmdStop
					return
				default:
					// Control not in our Accepts mask; ignore.
				}
			case <-served:
				// Serve loop returned without an SCM Stop (fatal error).
				// Ask the state machine to tear the service down cleanly.
				cmds <- svcCmdStop
				return
			}
		}
	}()

	serviceControlLoop(cmds,
		func() { changes <- svc.Status{State: svc.Running, Accepts: accepted} },
		func() { changes <- svc.Status{State: svc.StopPending} },
		cancel,
	)

	// Let the in-flight cycle finish draining before reporting Stopped, so the
	// SCM sees the same graceful shutdown the console path gives systemd.
	<-served
	changes <- svc.Status{State: svc.Stopped}
	return false, 0
}
