package osrelease

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTemp writes content to a fresh temp file and returns its path.
func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "kfile")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return p
}

// withKernelSeams points the /proc seams at the given paths for one test and
// restores them afterwards. An empty string means "leave pointing at a path
// that does not exist" (so the read fails, exercising the fallback / absent
// branches) without touching the real /proc.
func withKernelSeams(t *testing.T, osrelease, version string) {
	t.Helper()
	origOsrelease, origVersion := procKernelOsreleasePath, procVersionPath
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if osrelease == "" {
		osrelease = missing
	}
	if version == "" {
		version = missing
	}
	procKernelOsreleasePath, procVersionPath = osrelease, version
	t.Cleanup(func() {
		procKernelOsreleasePath, procVersionPath = origOsrelease, origVersion
	})
}

func TestKernelLinux_ProcSysOsrelease(t *testing.T) {
	p := writeTemp(t, "6.1.0-18-amd64\n")
	withKernelSeams(t, p, "")

	got, ok := readLinuxKernel()
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if got != "6.1.0-18-amd64" {
		t.Fatalf("got %q, want %q", got, "6.1.0-18-amd64")
	}
}

func TestKernelLinux_FallbackProcVersion(t *testing.T) {
	v := writeTemp(t, "Linux version 5.15.0-105-generic (buildd@lcy02-amd64-078) (gcc ...) #115-Ubuntu SMP\n")
	// Primary path absent → falls back to /proc/version.
	withKernelSeams(t, "", v)

	got, ok := readLinuxKernel()
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if got != "5.15.0-105-generic" {
		t.Fatalf("got %q, want %q", got, "5.15.0-105-generic")
	}
}

func TestKernelLinux_MalformedProcVersion(t *testing.T) {
	cases := []struct {
		name string
		data string
	}{
		{"no prefix", "totally bogus content\n"},
		{"prefix only, no token", "Linux version \n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := parseProcVersion([]byte(tc.data)); ok {
				t.Fatalf("ok = true (%q), want false", got)
			}
		})
	}
}

func TestKernelLinux_BothMissing(t *testing.T) {
	withKernelSeams(t, "", "")
	if got, ok := readLinuxKernel(); ok {
		t.Fatalf("ok = true (%q), want false when both /proc sources absent", got)
	}
}

func TestKernelLinux_CapAndTrim(t *testing.T) {
	long := strings.Repeat("a", 300)
	p := writeTemp(t, "  "+long+"  \n")
	withKernelSeams(t, p, "")

	got, ok := readLinuxKernel()
	if !ok {
		t.Fatal("ok = false, want true")
	}
	if len(got) != fieldCap {
		t.Fatalf("len = %d, want %d (capped)", len(got), fieldCap)
	}
	if strings.ContainsAny(got, " \t\n") {
		t.Fatalf("value %q still contains whitespace", got)
	}
}

func TestKernelLinux_RejectsControlBytes(t *testing.T) {
	// An embedded control byte must yield ok=false so a hostile /proc value
	// cannot smuggle raw bytes into the scan payload.
	if got, ok := sanitizeKernel("6.1.0\x00evil"); ok {
		t.Fatalf("ok = true (%q), want false for embedded NUL", got)
	}
	if got, ok := sanitizeKernel("6.1.0\x1bevil"); ok {
		t.Fatalf("ok = true (%q), want false for embedded ESC", got)
	}
}

func TestKernelLinux_SizeCap(t *testing.T) {
	// A file larger than the read cap is refused by safeio.ReadFile, so the
	// primary read returns an error and DetectKernel falls through to false
	// (no fallback file here).
	big := strings.Repeat("x", maxKernelFileSize+1)
	p := writeTemp(t, big)
	withKernelSeams(t, p, "")
	if got, ok := readLinuxKernel(); ok {
		t.Fatalf("ok = true (%q), want false for oversized /proc file", got)
	}
}
