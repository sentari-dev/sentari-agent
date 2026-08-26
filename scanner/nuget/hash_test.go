package nuget

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// TestScan_NupkgSha256 proves the retained .nupkg archive's SHA-256 lands on
// the coordinate's Sha256 (SBOM-completeness v2 §4.5).
func TestScan_NupkgSha256(t *testing.T) {
	root := t.TempDir()
	writeNuGetPkg(t, root, "Newtonsoft.Json", "13.0.3", "")
	// NuGet names the archive "<lower-id>.<version>.nupkg" beside the nuspec.
	nupkgContent := []byte("PK\x03\x04-fake-nupkg-bytes")
	nupkgPath := filepath.Join(root, "newtonsoft.json", "13.0.3", "newtonsoft.json.13.0.3.nupkg")
	if err := os.WriteFile(nupkgPath, nupkgContent, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(nupkgContent)
	want := hex.EncodeToString(sum[:])

	var s Scanner
	records, errs := s.Scan(context.Background(), scanner.Environment{
		EnvType: EnvNuGet,
		Name:    layoutGlobalPackages,
		Path:    root,
	})
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	var found bool
	for _, r := range records {
		if r.Name == "Newtonsoft.Json" {
			found = true
			if r.Sha256 != want {
				t.Errorf("sha256 = %q, want %q", r.Sha256, want)
			}
		}
	}
	if !found {
		t.Fatal("Newtonsoft.Json not emitted")
	}
}

// TestScan_NoNupkgNoHash confirms a restore-only cache without the archive
// leaves Sha256 empty (the field is then omitted on the wire).
func TestScan_NoNupkgNoHash(t *testing.T) {
	root := t.TempDir()
	writeNuGetPkg(t, root, "Serilog", "3.1.1", "")

	var s Scanner
	records, _ := s.Scan(context.Background(), scanner.Environment{
		EnvType: EnvNuGet,
		Name:    layoutGlobalPackages,
		Path:    root,
	})
	for _, r := range records {
		if r.Name == "Serilog" && r.Sha256 != "" {
			t.Errorf("sha256 = %q, want empty (no .nupkg present)", r.Sha256)
		}
	}
}
