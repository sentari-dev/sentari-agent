//go:build darwin

package osrelease

import "syscall"

// DetectKernel returns the Darwin kernel release (e.g. "24.5.0") via the
// kern.osrelease sysctl — a stdlib syscall, no exec and no cgo. Best-effort:
// ok=false on any failure.
func DetectKernel() (string, bool) {
	v, err := syscall.Sysctl("kern.osrelease")
	if err != nil {
		return "", false
	}
	return sanitizeKernel(v)
}
