//go:build linux

package osrelease

// DetectKernel returns the running kernel release (the uname -r equivalent)
// read from /proc data files — it never invokes uname or any other binary.
// Best-effort: ok=false on any failure, never an error, so kernel detection can
// never fail a scan.
func DetectKernel() (string, bool) {
	return readLinuxKernel()
}
