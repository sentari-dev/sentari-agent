//go:build windows

package comms

import (
	"net"
	"net/url"
	"os"
	"syscall"
	"testing"
)

// TestIsRetryable_WindowsConnRefused proves the Windows agent classifies
// a winsock connection-refused (WSAECONNREFUSED = 10061) as retryable.
// The regression this guards is subtle: Go's syscall.ECONNREFUSED on
// Windows is an invented placeholder value, so the old cross-platform
// errno check silently never matched and refused uploads were dropped
// after a single attempt during a server restart.
//
// NOTE: this test only runs under GOOS=windows.  On the darwin/linux
// dev + CI hosts it is compile-checked via `GOOS=windows go vet ./comms/`
// but not executed, so the assertion below is verified on Windows agents
// (or a windows CI runner) only.
func TestIsRetryable_WindowsConnRefused(t *testing.T) {
	// Reconstruct the error chain http.Client.Do produces for a refused
	// dial: url.Error → net.OpError → os.SyscallError → syscall.Errno.
	errno := syscall.Errno(10061) // WSAECONNREFUSED
	err := &url.Error{
		Op:  "Post",
		URL: "https://server.example/scan",
		Err: &net.OpError{
			Op:  "dial",
			Net: "tcp",
			Err: os.NewSyscallError("connect", errno),
		},
	}
	if !isRetryable(err) {
		t.Fatalf("WSAECONNREFUSED (10061) must be retryable on Windows, isRetryable=false")
	}

	// And connection-reset (WSAECONNRESET = 10054).
	reset := &url.Error{
		Op:  "Post",
		URL: "https://server.example/scan",
		Err: &net.OpError{
			Op:  "read",
			Net: "tcp",
			Err: os.NewSyscallError("wsarecv", syscall.Errno(10054)),
		},
	}
	if !isRetryable(reset) {
		t.Fatalf("WSAECONNRESET (10054) must be retryable on Windows, isRetryable=false")
	}
}

// TestIsRetryable_WindowsUnreachable proves the Windows agent classifies a
// winsock host-unreachable (WSAEHOSTUNREACH = 10065) and network-unreachable
// (WSAENETUNREACH = 10051) as retryable, so a link-recovery routing blip during
// an air-gap reconnect is retried within the cycle rather than dropped after a
// single attempt (finding offline-2).  Like the refused/reset case, the regression
// this guards is that Go's syscall.EHOSTUNREACH/ENETUNREACH on Windows are
// invented placeholder values that never match the real winsock codes.
//
// NOTE: runs under GOOS=windows only; compile-checked elsewhere via
// `GOOS=windows go vet ./comms/`.
func TestIsRetryable_WindowsUnreachable(t *testing.T) {
	cases := []struct {
		name  string
		op    string
		sysFn string
		errno syscall.Errno
	}{
		{"host unreachable", "dial", "connect", syscall.Errno(10065)},    // WSAEHOSTUNREACH
		{"network unreachable", "dial", "connect", syscall.Errno(10051)}, // WSAENETUNREACH
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := &url.Error{
				Op:  "Post",
				URL: "https://server.example/scan",
				Err: &net.OpError{
					Op:  tc.op,
					Net: "tcp",
					Err: os.NewSyscallError(tc.sysFn, tc.errno),
				},
			}
			if !isRetryable(err) {
				t.Fatalf("%s (%d) must be retryable on Windows, isRetryable=false", tc.name, tc.errno)
			}
		})
	}
}
