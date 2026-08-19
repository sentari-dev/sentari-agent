//go:build windows

package osrelease

import (
	"strconv"

	"golang.org/x/sys/windows"
)

// DetectKernel returns the Windows NT version as "<major>.<minor>.<build>"
// (e.g. "10.0.26100") via RtlGetNtVersionNumbers — a direct ntdll query that
// ignores the application-compatibility shim and never shells out.
// Best-effort: ok=false if the formatted value is empty.
func DetectKernel() (string, bool) {
	major, minor, build := windows.RtlGetNtVersionNumbers()
	v := strconv.FormatUint(uint64(major), 10) + "." +
		strconv.FormatUint(uint64(minor), 10) + "." +
		strconv.FormatUint(uint64(build), 10)
	return sanitizeKernel(v)
}
