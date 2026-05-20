package runtimeversions

import (
	"path/filepath"
	"testing"
)

func TestDetectJDKInDir_temurin17(t *testing.T) {
	dir := filepath.Join("testdata", "jdk", "temurin-17")
	got, err := DetectJDKInDir(dir)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if got == nil {
		t.Fatal("expected an InstalledRuntime, got nil")
	}
	if got.Name != "jdk" {
		t.Errorf("Name = %q, want jdk", got.Name)
	}
	if got.Version != "17.0.5" {
		t.Errorf("Version = %q, want 17.0.5", got.Version)
	}
	if got.Cycle != "17" {
		t.Errorf("Cycle = %q, want 17", got.Cycle)
	}
	if got.Distro != "Temurin" {
		t.Errorf("Distro = %q, want Temurin", got.Distro)
	}
	if got.InstallPath != dir {
		t.Errorf("InstallPath = %q, want %q", got.InstallPath, dir)
	}
}

func TestDetectJDKInDir_corretto8_legacyVersion(t *testing.T) {
	dir := filepath.Join("testdata", "jdk", "corretto-8")
	got, err := DetectJDKInDir(dir)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if got.Version != "1.8.0_392" || got.Cycle != "8" {
		t.Errorf("wrong version/cycle: %s / %s", got.Version, got.Cycle)
	}
	if got.Distro != "Corretto" {
		t.Errorf("Distro = %q, want Corretto", got.Distro)
	}
}

func TestDetectJDKInDir_missingReleaseFile(t *testing.T) {
	dir := t.TempDir() // empty dir
	got, err := DetectJDKInDir(dir)
	if err != nil {
		t.Fatalf("expected no error on missing release file, got %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestParseJDKDistroFromImplementor(t *testing.T) {
	cases := map[string]string{
		"Eclipse Adoptium":           "Temurin",
		"Amazon.com Inc.":            "Corretto",
		"Microsoft":                  "Microsoft",
		"Azul Systems, Inc.":         "Zulu",
		"AdoptOpenJDK":               "Temurin",
		"Oracle Corporation":         "Oracle",
		"":                           "",
		"Unknown Vendor":             "Unknown Vendor",
	}
	for in, want := range cases {
		if got := parseJDKDistroFromImplementor(in); got != want {
			t.Errorf("parseJDKDistroFromImplementor(%q) = %q, want %q", in, got, want)
		}
	}
}
