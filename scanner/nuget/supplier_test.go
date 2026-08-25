package nuget

import (
	"context"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// TestScan_AuthorsRoutedToSupplier proves the nuspec <authors> now lands on
// Supplier (the NTIA element) and no longer overloads InstallerUser — the
// SBOM-completeness v2 OQ-5 clean break.
func TestScan_AuthorsRoutedToSupplier(t *testing.T) {
	root := t.TempDir()
	writeNuGetPkg(t, root, "Newtonsoft.Json", "13.0.3", `<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Newtonsoft.Json</id>
    <version>13.0.3</version>
    <authors>James Newton-King</authors>
  </metadata>
</package>`)

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
			if r.Supplier != "James Newton-King" {
				t.Errorf("supplier = %q, want %q", r.Supplier, "James Newton-King")
			}
			if r.InstallerUser != "" {
				t.Errorf("installer_user = %q, want empty (authors no longer overloaded there)", r.InstallerUser)
			}
		}
	}
	if !found {
		t.Fatal("Newtonsoft.Json not emitted")
	}
}
