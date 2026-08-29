package hardening

import (
	"path/filepath"
	"testing"
)

// TestCollectKernel_Fixture reads the 8 kernel.* sysctls from a /proc/sys
// fixture root and asserts each scalar value + that all 8 keys are emitted.
func TestCollectKernel_Fixture(t *testing.T) {
	obs := collectKernel(filepath.Join("testdata", "procsys"))
	if len(obs) != len(kernelSysctls) {
		t.Fatalf("emitted %d kernel observations, want %d", len(obs), len(kernelSysctls))
	}
	want := map[string]string{
		"kernel.randomize_va_space": "2",
		"kernel.ip_forward":         "0",
		"kernel.accept_redirects":   "0",
		"kernel.send_redirects":     "0",
		"kernel.tcp_syncookies":     "1",
		"kernel.protected_symlinks": "1",
		"kernel.kptr_restrict":      "1",
		"kernel.rp_filter":          "1",
	}
	for key, val := range want {
		assertValue(t, mustObs(t, obs, key), val)
	}
	// Every kernel observation carries file provenance + sha.
	for _, o := range obs {
		if o.SourcePath == nil || o.SourceSHA256 == nil {
			t.Errorf("%s: missing provenance (path=%v sha=%v)", o.Key, o.SourcePath, o.SourceSHA256)
		}
	}
}

// TestCollectKernel_MissingRoot: a namespaced/hardened /proc where the scalars
// are absent yields unknown for every key (null value + "not found").
func TestCollectKernel_MissingRoot(t *testing.T) {
	obs := collectKernel(filepath.Join(t.TempDir(), "empty-procsys"))
	if len(obs) != len(kernelSysctls) {
		t.Fatalf("emitted %d, want %d", len(obs), len(kernelSysctls))
	}
	for _, o := range obs {
		assertUnknown(t, o, "not found")
	}
}

// TestCollectKernel_VectorScalar: rp_filter/redirects can be tab-separated
// vectors on some kernels; the collector keeps the first (all-scope) field.
func TestCollectKernel_VectorScalar(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "procsys")
	// Overwrite rp_filter with a multi-field vector.
	writeTemp(t, root, "net/ipv4/conf/all/rp_filter", "1\t2\t0\n")
	// Provide the remaining 7 so the collector reads them without error is
	// irrelevant here; we only assert the vector-handling key.
	obs := collectKernel(root)
	assertValue(t, mustObs(t, obs, "kernel.rp_filter"), "1")
}
