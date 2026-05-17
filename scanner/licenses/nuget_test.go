package licenses

import (
	"path/filepath"
	"testing"
)

func TestExtractNuGet_spdxExpression(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "newtonsoft.json", "13.0.3")
	mustMkdir(t, dir)
	mustWrite(t, filepath.Join(dir, "Newtonsoft.Json.nuspec"), `<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Newtonsoft.Json</id>
    <version>13.0.3</version>
    <license type="expression">MIT</license>
  </metadata>
</package>`)
	out, err := ExtractNuGet(root)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if len(out) != 1 || out[0].SpdxID != "MIT" || out[0].Confidence != 0.9 {
		t.Errorf("wrong: %+v", out)
	}
}

func TestExtractNuGet_licenseUrlFallback(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "old.pkg", "1.0.0")
	mustMkdir(t, dir)
	mustWrite(t, filepath.Join(dir, "Old.Pkg.nuspec"), `<?xml version="1.0"?>
<package><metadata><id>Old.Pkg</id><version>1.0.0</version><licenseUrl>https://opensource.org/licenses/MIT</licenseUrl></metadata></package>`)
	out, err := ExtractNuGet(root)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if len(out) != 1 || out[0].Confidence != 0.5 || out[0].RawText != "https://opensource.org/licenses/MIT" {
		t.Errorf("wrong: %+v", out)
	}
}
