package supplychain

import (
	"context"
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
	signals, err := DetectInNuGetCache(context.Background(), root)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if len(signals) != 1 || signals[0].PackageName != "Newtonsoft.Json" || signals[0].PackageVersion != "13.0.3" {
		t.Fatalf("expected 1 unsigned signal for Newtonsoft.Json/13.0.3, got %+v", signals)
	}
}

// TestDetectInNuGetCache_malformedNuspec feeds truncated, garbage, and
// wrong-shaped .nuspec XML and asserts the walker degrades gracefully: no
// panic and no fabricated signal from XML it cannot parse. A NuGet cache is
// attacker-influenceable, so a crash or a bogus coordinate here corrupts the
// supply-chain report.
func TestDetectInNuGetCache_malformedNuspec(t *testing.T) {
	cases := []struct {
		name    string
		content string
	}{
		{"empty", ""},
		{"whitespace only", "   \n\t\n"},
		{"truncated element", `<package><metadata><id>Foo`},
		{"unclosed root", `<package><metadata><id>Foo</id><version>1.0.0</version></metadata>`},
		{"garbage tokens", `not xml <<< >>> @@@`},
		{"control bytes", "\x00\x01\x02<package/>"},
		{"missing metadata", `<package></package>`},
		{"missing id", `<package><metadata><version>1.0.0</version></metadata></package>`},
		{"empty id", `<package><metadata><id></id><version>1.0.0</version></metadata></package>`},
		{"mismatched close tag", `<package><metadata><id>Foo</version></metadata></package>`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			verDir := filepath.Join(root, "somepkg", "1.0.0")
			mustMkdir(t, verDir)
			mustWrite(t, filepath.Join(verDir, "Some.Pkg.nuspec"), tc.content)
			// Must neither panic nor fabricate a signal from unparsable XML.
			signals, err := DetectInNuGetCache(context.Background(), root)
			if err != nil {
				t.Fatalf("detect returned error on malformed nuspec: %v", err)
			}
			if len(signals) != 0 {
				t.Errorf("expected no signals for malformed nuspec %q, got %+v", tc.name, signals)
			}
		})
	}
}

func TestDetectInNuGetCache_signedSkipped(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "signed.pkg", "1.0.0")
	mustMkdir(t, pkgDir)
	mustWrite(t, filepath.Join(pkgDir, "Signed.Pkg.nuspec"), `<?xml version="1.0"?>
<package><metadata><id>Signed.Pkg</id><version>1.0.0</version></metadata></package>`)
	mustWrite(t, filepath.Join(pkgDir, ".signature.p7s"), "fake sig bytes")
	signals, err := DetectInNuGetCache(context.Background(), root)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if len(signals) != 0 {
		t.Errorf("signed package should yield no signals, got %+v", signals)
	}
}
