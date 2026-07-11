//go:build !windows

package comms

import (
	"net"
	"net/url"
	"os"
	"syscall"
	"testing"
)

// syscallDialErr reconstructs the error chain http.Client.Do produces for
// a failed dial/read on POSIX hosts: url.Error → net.OpError →
// os.SyscallError → syscall.Errno.  This mirrors the Windows variant's
// helper so both platforms assert over a realistic wrapped chain.
func syscallDialErr(op string, errno syscall.Errno) error {
	return &url.Error{
		Op:  "Post",
		URL: "https://server.example/scan",
		Err: &net.OpError{
			Op:  op,
			Net: "tcp",
			Err: os.NewSyscallError("connect", errno),
		},
	}
}

// TestIsTransientSyscallErr_Unix covers the POSIX errno classification
// (retry_errno_unix.go) which previously had zero test coverage — only
// the Windows WSA* variant was exercised.  ECONNREFUSED/ECONNRESET and the
// host-/network-unreachable errnos are the transient transport failures worth
// retrying (server restart, pod rollover, and a link-recovery routing blip
// during an air-gap reconnect); anything else (here EPERM) is not.
func TestIsTransientSyscallErr_Unix(t *testing.T) {
	cases := []struct {
		name  string
		errno syscall.Errno
		want  bool
	}{
		{"connection refused", syscall.ECONNREFUSED, true},
		{"connection reset", syscall.ECONNRESET, true},
		{"host unreachable", syscall.EHOSTUNREACH, true},
		{"network unreachable", syscall.ENETUNREACH, true},
		{"permission denied is not transient", syscall.EPERM, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Assert both the direct errno and the wrapped dial chain, so
			// the build-tagged helper and the errors.Is traversal are both
			// covered.
			if got := isTransientSyscallErr(tc.errno); got != tc.want {
				t.Fatalf("isTransientSyscallErr(bare %v) = %v, want %v", tc.name, got, tc.want)
			}
			if got := isTransientSyscallErr(syscallDialErr("dial", tc.errno)); got != tc.want {
				t.Fatalf("isTransientSyscallErr(wrapped %v) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

// TestIsRetryable_UnixConnErrnos is the end-to-end assertion: a refused or
// reset dial wrapped in the full url.Error chain is retryable, while a
// non-transient errno (EPERM) surfaces to the caller unchanged.
func TestIsRetryable_UnixConnErrnos(t *testing.T) {
	if !isRetryable(syscallDialErr("dial", syscall.ECONNREFUSED)) {
		t.Fatal("ECONNREFUSED dial must be retryable")
	}
	if !isRetryable(syscallDialErr("read", syscall.ECONNRESET)) {
		t.Fatal("ECONNRESET read must be retryable")
	}
	if !isRetryable(syscallDialErr("dial", syscall.EHOSTUNREACH)) {
		t.Fatal("EHOSTUNREACH dial must be retryable")
	}
	if !isRetryable(syscallDialErr("dial", syscall.ENETUNREACH)) {
		t.Fatal("ENETUNREACH dial must be retryable")
	}
	if isRetryable(syscallDialErr("dial", syscall.EPERM)) {
		t.Fatal("EPERM dial must NOT be retryable")
	}
}
