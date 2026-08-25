package npm

import (
	"context"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// TestScan_ExtractsSupplier proves the manifest `author` field (both the
// string "Name <email> (url)" shape and the object {name,…} shape) lands on
// PackageRecord.Supplier with email/URL noise stripped (SBOM-completeness v2).
func TestScan_ExtractsSupplier(t *testing.T) {
	root := t.TempDir()
	writePkg(t, root, "string-author", "1.0.0", map[string]any{
		"author": "Sindre Sorhus <sindre@sindresorhus.com> (https://sindresorhus.com)",
	})
	writePkg(t, root, "object-author", "1.0.0", map[string]any{
		"author": map[string]any{"name": "Acme Corp", "email": "dev@acme.com"},
	})
	writePkg(t, root, "no-author", "1.0.0", map[string]any{"license": "MIT"})

	var s Scanner
	records, _ := s.Scan(context.Background(), scanner.Environment{
		Name: layoutNodeModules,
		Path: root,
	})
	suppliers := map[string]string{}
	for _, r := range records {
		suppliers[r.Name] = r.Supplier
	}
	if suppliers["string-author"] != "Sindre Sorhus" {
		t.Errorf("string-author supplier = %q, want %q", suppliers["string-author"], "Sindre Sorhus")
	}
	if suppliers["object-author"] != "Acme Corp" {
		t.Errorf("object-author supplier = %q, want %q", suppliers["object-author"], "Acme Corp")
	}
	if suppliers["no-author"] != "" {
		t.Errorf("no-author supplier = %q, want empty", suppliers["no-author"])
	}
}
