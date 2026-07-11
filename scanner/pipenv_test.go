package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// TestScanPipenvEnvironment_HyphenatedNameLicense verifies that a package
// whose name contains a hyphen (typing-extensions) resolves its license from
// the wheel-normalized dist-info dir (typing_extensions-<v>.dist-info) rather
// than falling back to LicenseTier "unknown".
func TestScanPipenvEnvironment_HyphenatedNameLicense(t *testing.T) {
	envDir := t.TempDir()

	lock := `{
  "_meta": {"requires": {"python_version": "3.11"}},
  "default": {
    "typing-extensions": {"version": "==4.9.0"}
  },
  "develop": {}
}`
	if err := os.WriteFile(filepath.Join(envDir, "Pipfile.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	// Install METADATA under the wheel-normalized dist-info dir name
	// (underscores, not hyphens).
	distInfo := filepath.Join(envDir, ".venv", "lib", "python3.11", "site-packages",
		"typing_extensions-4.9.0.dist-info")
	if err := os.MkdirAll(distInfo, 0o755); err != nil {
		t.Fatal(err)
	}
	metadata := "Metadata-Version: 2.1\nName: typing_extensions\nVersion: 4.9.0\nLicense: PSF-2.0\n"
	if err := os.WriteFile(filepath.Join(distInfo, "METADATA"), []byte(metadata), 0o644); err != nil {
		t.Fatal(err)
	}

	packages, errs := scanPipenvEnvironment(envDir)
	if len(errs) != 0 {
		t.Fatalf("unexpected scan errors: %v", errs)
	}

	var found *PackageRecord
	for i := range packages {
		if packages[i].Name == "typing-extensions" {
			found = &packages[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("typing-extensions not found in %d packages", len(packages))
	}
	if found.LicenseTier == "unknown" || found.LicenseTier == "" {
		t.Errorf("LicenseTier = %q, want a real tier (dist-info name normalization missed)", found.LicenseTier)
	}
	if found.LicenseSPDX != "PSF-2.0" {
		t.Errorf("LicenseSPDX = %q, want PSF-2.0", found.LicenseSPDX)
	}
	if found.LicenseTier != "permissive" {
		t.Errorf("LicenseTier = %q, want permissive", found.LicenseTier)
	}
}
