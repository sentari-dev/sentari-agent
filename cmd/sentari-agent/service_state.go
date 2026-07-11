//go:build enterprise

package main

// serviceName is the Windows service identifier registered by install.ps1
// (New-Service -Name SentariAgent, the default $ServiceName) and by
// restart_windows.go's self-update restart helper.  It is passed to svc.Run so
// the SCM dispatch table advertises the matching name.  Declared here in
// OS-agnostic code so the portable control-loop tests can reference it without
// a windows build tag.  (For a SERVICE_WIN32_OWN_PROCESS service the SCM
// dispatches by process rather than by this name, but keeping it consistent
// with the registered name avoids confusion in Event Viewer diagnostics.)
const serviceName = "SentariAgent"

// svcControlCmd is an OS-agnostic control request fed to serviceControlLoop.
// On Windows it is translated from svc.ChangeRequest (service_windows.go); the
// portable enum keeps the shutdown state machine free of the windows-only svc
// types so it compiles and is unit-testable on every host, including this
// darwin CI runner.
type svcControlCmd int

const (
	// svcCmdInterrogate asks the service to re-report its current status.
	svcCmdInterrogate svcControlCmd = iota
	// svcCmdStop asks the service to shut down gracefully (SCM Stop or
	// Shutdown, or the serve loop exiting on its own).
	svcCmdStop
)

// serviceControlLoop is the OS-agnostic SCM control state machine.  It consumes
// control requests until a stop is received (or the request channel closes):
//
//   - svcCmdStop  → reportStopPending(), then cancel() to tear down the shared
//     serve-loop root context (the same cancellation SIGTERM triggers on POSIX),
//     then return.
//   - anything else (svcCmdInterrogate) → reportRunning() to echo the live
//     status back to the SCM, then keep looping.
//
// Factoring the state machine here — behind an injectable request channel and
// injected report/cancel callbacks — lets us unit-test the Stop→cancel→
// StopPending transition without a real Service Control Manager.  The Windows
// handler (service_windows.go) supplies the real channel and callbacks; the
// test supplies fakes.
func serviceControlLoop(reqs <-chan svcControlCmd, reportRunning, reportStopPending, cancel func()) {
	for cmd := range reqs {
		switch cmd {
		case svcCmdStop:
			reportStopPending()
			cancel()
			return
		default:
			reportRunning()
		}
	}
}
