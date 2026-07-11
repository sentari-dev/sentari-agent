//go:build windows

package comms

import (
	"errors"

	"golang.org/x/sys/windows"
)

// isTransientSyscallErr reports whether err's chain contains a winsock
// connection-refused, connection-reset, or host-/network-unreachable error —
// the transient transport failures worth a retry (server restart, pod rollover,
// and a link-recovery routing blip during an air-gap reconnect, where the
// unreachable codes fire briefly until the route is re-established).
//
// This is deliberately build-tagged.  DO NOT fold it back into a single
// cross-platform file: Go's syscall.ECONNREFUSED/ECONNRESET (and the
// unreachable errnos) on Windows are invented APPLICATION_ERROR placeholder
// values (not the real winsock codes), so an errors.Is against them never
// matches a live network error and connection-refused/reset/unreachable uploads
// would never be classified retryable.  winsock reports these as
// WSAECONNREFUSED (10061) / WSAECONNRESET (10054) / WSAEHOSTUNREACH (10065) /
// WSAENETUNREACH (10051); we match those instead.
func isTransientSyscallErr(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED) ||
		errors.Is(err, windows.WSAECONNRESET) ||
		errors.Is(err, windows.WSAEHOSTUNREACH) ||
		errors.Is(err, windows.WSAENETUNREACH)
}
