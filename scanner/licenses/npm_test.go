package licenses

import (
	"path/filepath"
	"testing"
)

func TestExtractNpm_spdxString(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "lodash")
	mustMkdir(t, pkg)
	mustWrite(t, filepath.Join(pkg, "package.json"), `{"name":"lodash","version":"4.17.21","license":"MIT"}`)
	out, err := ExtractNpm(root)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if len(out) != 1 || out[0].SpdxID != "MIT" || out[0].Confidence != 0.95 {
		t.Errorf("wrong: %+v", out)
	}
}

func TestExtractNpm_licenseObjectForm(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "old-pkg")
	mustMkdir(t, pkg)
	mustWrite(t, filepath.Join(pkg, "package.json"), `{"name":"old-pkg","version":"1.0.0","license":{"type":"BSD","url":"http://x"}}`)
	out, err := ExtractNpm(root)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if len(out) != 1 || out[0].SpdxID != "BSD" || out[0].Confidence != 0.7 {
		t.Errorf("wrong: %+v", out)
	}
}

func TestExtractNpm_licensesArrayForm(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "dual")
	mustMkdir(t, pkg)
	mustWrite(t, filepath.Join(pkg, "package.json"), `{"name":"dual","version":"1.0.0","licenses":[{"type":"MIT"},{"type":"Apache-2.0"}]}`)
	out, err := ExtractNpm(root)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 evidences, got %d: %+v", len(out), out)
	}
}
