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
	if e.RawText != "MIT License" || e.Source != "spdx_pkg" || e.SpdxID != "" || e.Confidence != 0.5 {
		t.Errorf("wrong fallback evidence: %+v", e)
	}
}

func TestExtractNpm_licenseFileFallbackDetectsTitlelessMIT(t *testing.T) {
	// The dominant MIT LICENSE template opens with the copyright line — no
	// title — followed by the hereby-granted clause. The body-signature scan
	// has to recognise it from the body, not give up on the first line.
	root := t.TempDir()
	pkg := filepath.Join(root, "bare-mit")
	mustMkdir(t, pkg)
	mustWrite(t, filepath.Join(pkg, "package.json"), `{"name":"bare-mit","version":"1.0.0"}`)
	mustWrite(t, filepath.Join(pkg, "LICENSE"),
		"Copyright (c) 2020 Someone\n\nPermission is hereby granted, free of charge, to any person obtaining a copy of this software...\n")
	out, err := ExtractNpm(root)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if len(out) != 1 || out[0].RawText != "MIT License" || out[0].Source != "spdx_pkg" {
		t.Errorf("expected title-less MIT to be detected as 'MIT License', got: %+v", out)
	}
}

func TestExtractNpm_licenseFileFallbackBodySignatures(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"apache-2.0", "Apache License\nVersion 2.0, January 2004\nhttp://...", "Apache-2.0"},
		{"isc", "Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee...", "ISC"},
		{"bsd-3-clause", "Redistribution and use in source and binary forms, with or without modification...\nNeither the name of the project may be used to endorse or promote products...", "BSD-3-Clause"},
		{"bsd-2-clause", "Redistribution and use in source and binary forms, with or without modification, are permitted...\nTHIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AS IS...", "BSD-2-Clause"},
		{"gpl-3", "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n...", "GPL-3.0-only"},
		{"lgpl-3", "GNU LESSER GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007\n...", "LGPL-3.0-only"},
		{"agpl-3", "GNU AFFERO GENERAL PUBLIC LICENSE\nVersion 3, 19 November 2007\n...", "AGPL-3.0-only"},
		{"mpl-2.0", "Mozilla Public License\nVersion 2.0\n...", "MPL-2.0"},
		{"unlicense", "This is free and unencumbered software released into the public domain.\n...", "Unlicense"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			pkg := filepath.Join(root, c.name)
			mustMkdir(t, pkg)
			mustWrite(t, filepath.Join(pkg, "package.json"), `{"name":"`+c.name+`","version":"1.0.0"}`)
			mustWrite(t, filepath.Join(pkg, "LICENSE"), c.body)
			out, err := ExtractNpm(root)
			if err != nil {
				t.Fatalf("extract: %v", err)
			}
			if len(out) != 1 || out[0].RawText != c.want {
				t.Errorf("body signature for %s: expected %q, got %+v", c.name, c.want, out)
			}
		})
	}
}

func TestExtractNpm_licenseFileFallbackTitleLineWhenNoSignature(t *testing.T) {
	// File doesn't match any body signature, but opens with a title line ->
	// we still emit the title (server may or may not normalize it).
	root := t.TempDir()
	pkg := filepath.Join(root, "titled")
	mustMkdir(t, pkg)
	mustWrite(t, filepath.Join(pkg, "package.json"), `{"name":"titled","version":"1.0.0"}`)
	mustWrite(t, filepath.Join(pkg, "LICENSE"), "Some Custom License\n\nBlah blah, terms.\n")
	out, err := ExtractNpm(root)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(out) != 1 || out[0].RawText != "Some Custom License" {
		t.Errorf("expected title-line fallback, got: %+v", out)
	}
}

func TestExtractNpm_licenseFileFallbackEmptyWhenNoSignal(t *testing.T) {
	// No body signature AND first line is a copyright -> no evidence.
	root := t.TempDir()
	pkg := filepath.Join(root, "nope")
	mustMkdir(t, pkg)
	mustWrite(t, filepath.Join(pkg, "package.json"), `{"name":"nope","version":"1.0.0"}`)
	mustWrite(t, filepath.Join(pkg, "LICENSE"), "Copyright (c) 2020 Someone\n\nAll rights reserved.\n")
	out, err := ExtractNpm(root)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected no evidence for truly unmappable license, got: %+v", out)
	}
}

// TestExtractNpm_licenseFileFallbackUsesAllowedSource guards the
// license-provenance contract: the 4 Phase-3 ecosystems (incl. npm) MUST
// NOT emit the reserved `copyright_file` / `rpm_header` / `server_enriched`
// source values. The LICENSE-file fallback must use an agent-allowed source.
func TestExtractNpm_licenseFileFallbackUsesAllowedSource(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "fallback-src")
	mustMkdir(t, pkg)
	mustWrite(t, filepath.Join(pkg, "package.json"), `{"name":"fallback-src","version":"1.0.0"}`)
	mustWrite(t, filepath.Join(pkg, "LICENSE"), "MIT License\n\nCopyright (c) 2020 Someone\n")
	out, err := ExtractNpm(root)
	if err != nil {
		t.Fatalf("extract failed: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("expected 1 fallback evidence, got %d: %+v", len(out), out)
	}
	forbidden := map[string]bool{"copyright_file": true, "rpm_header": true, "server_enriched": true}
	allowed := map[string]bool{"spdx_pkg": true, "trove": true, "pom": true, "nuspec": true}
	if forbidden[out[0].Source] {
		t.Errorf("fallback emitted contract-forbidden source %q", out[0].Source)
	}
	if !allowed[out[0].Source] {
		t.Errorf("fallback emitted non-allowed source %q (want one of spdx_pkg/trove/pom/nuspec)", out[0].Source)
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
