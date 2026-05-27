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

func TestExtractNpm_licenseFileFallback(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "no-field")
	mustMkdir(t, pkg)
	// package.json with NO license/licenses field.
	mustWrite(t, filepath.Join(pkg, "package.json"), `{"name":"no-field","version":"2.0.0"}`)
	mustWrite(t, filepath.Join(pkg, "LICENSE"), "MIT License\n\nCopyright (c) 2020 Someone\n")
	out, err := ExtractNpm(root)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 fallback evidence, got %d: %+v", len(out), out)
	}
	e := out[0]
	if e.RawText != "MIT License" || e.Source != "copyright_file" || e.SpdxID != "" || e.Confidence != 0.5 {
		t.Errorf("wrong fallback evidence: %+v", e)
	}
}

func TestExtractNpm_licenseFileFallbackSkipsBareCopyright(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "bare")
	mustMkdir(t, pkg)
	mustWrite(t, filepath.Join(pkg, "package.json"), `{"name":"bare","version":"1.0.0"}`)
	// Title-less license file — opens with a copyright line the server can't map.
	mustWrite(t, filepath.Join(pkg, "LICENSE"), "Copyright (c) 2020 Someone\n\nPermission is hereby granted...\n")
	out, err := ExtractNpm(root)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected no evidence for bare-copyright license file, got: %+v", out)
	}
}

func TestExtractNpm_packageJSONLicenseWinsOverFile(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "both")
	mustMkdir(t, pkg)
	mustWrite(t, filepath.Join(pkg, "package.json"), `{"name":"both","version":"1.0.0","license":"ISC"}`)
	mustWrite(t, filepath.Join(pkg, "LICENSE"), "MIT License\n")
	out, err := ExtractNpm(root)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if len(out) != 1 || out[0].SpdxID != "ISC" || out[0].Source != "spdx_pkg" {
		t.Errorf("package.json license should win, got: %+v", out)
	}
}
