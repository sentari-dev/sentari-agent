package scanner

import (
	"encoding/json"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner/osrelease"
)

// withDetectSeams overrides the distro and kernel detector seams for one test.
func withDetectSeams(t *testing.T, distro func() (osrelease.Result, bool), kernel func() (string, bool)) {
	t.Helper()
	origD, origK := osReleaseDetect, kernelDetect
	osReleaseDetect, kernelDetect = distro, kernel
	t.Cleanup(func() { osReleaseDetect, kernelDetect = origD, origK })
}

func distroFound() (osrelease.Result, bool) {
	return osrelease.Result{ID: "debian", VersionID: "12"}, true
}
func distroAbsent() (osrelease.Result, bool) { return osrelease.Result{}, false }
func kernelFound() (string, bool)            { return "6.1.0-18-amd64", true }
func kernelAbsent() (string, bool)           { return "", false }

func TestScan_OsReleaseCarriesKernel(t *testing.T) {
	withDetectSeams(t, distroFound, kernelFound)
	got := detectOsReleasePayload()
	want := &OsRelease{ID: "debian", VersionID: "12", Kernel: "6.1.0-18-amd64"}
	if got == nil || *got != *want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestScan_KernelOnlyStillEmitsOsRelease(t *testing.T) {
	withDetectSeams(t, distroAbsent, kernelFound)
	got := detectOsReleasePayload()
	if got == nil {
		t.Fatal("os_release nil; want kernel-only payload")
	}
	if got.ID != "" || got.VersionID != "" {
		t.Fatalf("distro fields not empty: %+v", got)
	}
	if got.Kernel != "6.1.0-18-amd64" {
		t.Fatalf("kernel = %q, want %q", got.Kernel, "6.1.0-18-amd64")
	}
}

func TestScan_NeitherOmitsOsRelease(t *testing.T) {
	withDetectSeams(t, distroAbsent, kernelAbsent)
	if got := detectOsReleasePayload(); got != nil {
		t.Fatalf("os_release = %+v, want nil when neither detected", got)
	}
}

func TestScan_DistroOnlyOldShape(t *testing.T) {
	withDetectSeams(t, distroFound, kernelAbsent)
	got := detectOsReleasePayload()
	if got == nil {
		t.Fatal("os_release nil; want distro-only payload")
	}
	if got.Kernel != "" {
		t.Fatalf("kernel = %q, want empty (omitempty keeps old wire shape)", got.Kernel)
	}

	// Marshaled distro-only object must be byte-identical to the pre-kernel
	// wire shape: exactly {id, version_id}, no kernel key.
	body, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(body) != `{"id":"debian","version_id":"12"}` {
		t.Fatalf("wire = %s, want distro-only object without kernel key", body)
	}
}
