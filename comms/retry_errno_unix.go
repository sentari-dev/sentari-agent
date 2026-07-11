//go:build !windows

package comms

import (
	"errors"
	"syscall"
)

// isTransientSyscallErr reports whether err's chain contains a
// connection-refused, connection-reset, or host-/network-unreachable syscall
// errno — the transient transport failures worth a retry (server restart, pod
// rollover, and a link-recovery routing blip during an air-gap reconnect, where
// EHOSTUNREACH/ENETUNREACH fire briefly until the route is re-established).
//
// This is deliberately build-tagged.  DO NOT fold it back into a single
// cross-platform file: on Windows, syscall.ECONNREFUSED/ECONNRESET (and the
// unreachable errnos) are invented APPLICATION_ERROR placeholder values that
// never match a real winsock error, so the errno match must use the WSA* codes
// there (see retry_errno_windows.go).  A "simplification" that keeps only these
// POSIX constants silently makes refused/reset/unreachable uploads non-retryable
// on every Windows agent.
func isTransientSyscallErr(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH)
}
