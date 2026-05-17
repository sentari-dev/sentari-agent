package supplychain

import (
	"path/filepath"
	"testing"
)

func TestDetectInNuGetCache_unsigned(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "newtonsoft.json", "13.0.3")
	mustMkdir(t, pkgDir)
	mustWrite(t, filepath.Join(pkgDir, "Newtonsoft.Json.nuspec"), `<?xml version="1.0"?>
<package xmlns="http://schemas.microsoft.com/packaging/2013/05/nuspec.xsd">
  <metadata>
    <id>Newtonsoft.Json</id>
    <version>13.0.3</version>
  </metadata>
</package>`)
	signals, err := DetectInNuGetCache(root)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if len(signals) != 1 || signals[0].PackageName != "Newtonsoft.Json" || signals[0].PackageVersion != "13.0.3" {
		t.Fatalf("expected 1 unsigned signal for Newtonsoft.Json/13.0.3, got %+v", signals)
	}
}

func TestDetectInNuGetCache_signedSkipped(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "signed.pkg", "1.0.0")
	mustMkdir(t, pkgDir)
	mustWrite(t, filepath.Join(pkgDir, "Signed.Pkg.nuspec"), `<?xml version="1.0"?>
<package><metadata><id>Signed.Pkg</id><version>1.0.0</version></metadata></package>`)
	mustWrite(t, filepath.Join(pkgDir, ".signature.p7s"), "fake sig bytes")
	signals, err := DetectInNuGetCache(root)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if len(signals) != 0 {
		t.Errorf("signed package should yield no signals, got %+v", signals)
	}
}
