package licenses

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractPyPI_pep639LicenseExpressionPreferred(t *testing.T) {
	site := t.TempDir()
	dist := filepath.Join(site, "requests-2.31.0.dist-info")
	mustMkdir(t, dist)
	mustWrite(t, filepath.Join(dist, "METADATA"), "Metadata-Version: 2.3\nName: requests\nVersion: 2.31.0\nLicense-Expression: Apache-2.0\nLicense: Old text\nClassifier: License :: OSI Approved :: Apache Software License\n")
	out, err := ExtractPyPI(site)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 evidence (PEP 639 preferred), got %d: %+v", len(out), out)
	}
	if out[0].SpdxID != "Apache-2.0" || out[0].Source != "spdx_pkg" || out[0].Confidence != 0.95 {
		t.Errorf("wrong: %+v", out[0])
	}
}

func TestExtractPyPI_licenseHeaderFallback(t *testing.T) {
	site := t.TempDir()
	dist := filepath.Join(site, "lib-1.0.0.dist-info")
	mustMkdir(t, dist)
	mustWrite(t, filepath.Join(dist, "METADATA"), "Metadata-Version: 2.1\nName: lib\nVersion: 1.0.0\nLicense: MIT License\n")
	out, err := ExtractPyPI(site)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if len(out) != 1 || out[0].Source != "spdx_pkg" || out[0].Confidence != 0.7 || out[0].RawText != "MIT License" {
		t.Errorf("wrong: %+v", out)
	}
}

func TestExtractPyPI_troveFallbackWhenNoLicenseFields(t *testing.T) {
	site := t.TempDir()
	dist := filepath.Join(site, "old-1.0.0.dist-info")
	mustMkdir(t, dist)
	mustWrite(t, filepath.Join(dist, "METADATA"), "Metadata-Version: 2.1\nName: old\nVersion: 1.0.0\nClassifier: License :: OSI Approved :: BSD License\nClassifier: License :: OSI Approved :: Apache Software License\n")
	out, err := ExtractPyPI(site)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 trove evidences, got %d: %+v", len(out), out)
	}
	for _, e := range out {
		if e.Source != "trove" || e.Confidence != 0.6 {
			t.Errorf("wrong source/confidence: %+v", e)
		}
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
