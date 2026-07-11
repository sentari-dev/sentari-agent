package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeDistInfoName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"typing-extensions", "typing_extensions"},
		{"typing_extensions", "typing_extensions"},
		{"ruamel.yaml", "ruamel_yaml"},
		{"Jinja2", "jinja2"},
		{"zope.interface", "zope_interface"},
		{"backports.zoneinfo", "backports_zoneinfo"},
		{"Flask--SQLAlchemy", "flask_sqlalchemy"}, // runs of separators collapse
		{"requests", "requests"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := normalizeDistInfoName(tc.in); got != tc.want {
				t.Errorf("normalizeDistInfoName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestScanPoetryEnvironment_HyphenatedNameLicense verifies that a package
// whose name contains a hyphen (typing-extensions) resolves its license from
// the wheel-normalized dist-info dir (typing_extensions-<v>.dist-info) rather
// than falling back to LicenseTier "unknown".
func TestScanPoetryEnvironment_HyphenatedNameLicense(t *testing.T) {
	envDir := t.TempDir()

	lock := `[[package]]
name = "typing-extensions"
version = "4.9.0"
description = "Backported and Experimental Type Hints"
`
	if err := os.WriteFile(filepath.Join(envDir, "poetry.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	// Install METADATA under the wheel-normalized dist-info dir name
	// (underscores, not hyphens).
	distInfo := filepath.Join(envDir, ".venv", "lib", "python3.11", "site-packages",
		"typing_extensions-4.9.0.dist-info")
	if err := os.MkdirAll(distInfo, 0o755); err != nil {
		t.Fatal(err)
	}
	metadata := "Metadata-Version: 2.1\nName: typing_extensions\nVersion: 4.9.0\nLicense: PSF-2.0\n"
	if err := os.WriteFile(filepath.Join(distInfo, "METADATA"), []byte(metadata), 0o644); err != nil {
		t.Fatal(err)
	}

	packages, errs := scanPoetryEnvironment(envDir)
	if len(errs) != 0 {
		t.Fatalf("unexpected scan errors: %v", errs)
	}

	var found *PackageRecord
	for i := range packages {
		if packages[i].Name == "typing-extensions" {
			found = &packages[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("typing-extensions not found in %d packages", len(packages))
	}
	if found.LicenseTier == "unknown" || found.LicenseTier == "" {
		t.Errorf("LicenseTier = %q, want a real tier (dist-info name normalization missed)", found.LicenseTier)
	}
	if found.LicenseSPDX != "PSF-2.0" {
		t.Errorf("LicenseSPDX = %q, want PSF-2.0", found.LicenseSPDX)
	}
	if found.LicenseTier != "permissive" {
		t.Errorf("LicenseTier = %q, want permissive", found.LicenseTier)
	}
}

// TestGetPoetryInterpreterVersion_PEP621RequiresPython verifies that a modern
// PEP 621 / Poetry 2.x project — which declares the interpreter under
// [project] requires-python and may omit [tool.poetry] entirely — resolves a
// CONCRETE interpreter version from its .venv/pyvenv.cfg rather than echoing
// the bare requires-python constraint.
func TestGetPoetryInterpreterVersion_PEP621RequiresPython(t *testing.T) {
	envDir := t.TempDir()

	pyproject := `[project]
name = "modern-app"
version = "0.1.0"
requires-python = ">=3.9"

[build-system]
requires = ["poetry-core"]
build-backend = "poetry.core.masonry.api"
`
	if err := os.WriteFile(filepath.Join(envDir, "pyproject.toml"), []byte(pyproject), 0o644); err != nil {
		t.Fatal(err)
	}

	// The project's .venv pins the concrete interpreter (uv-style version_info).
	venv := filepath.Join(envDir, ".venv")
	if err := os.MkdirAll(venv, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(venv, "pyvenv.cfg"),
		[]byte("home = /usr/bin\nversion_info = 3.12.4.final.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := getPoetryInterpreterVersion(envDir); got != "3.12.4" {
		t.Errorf("getPoetryInterpreterVersion() = %q, want concrete 3.12.4 from pyvenv.cfg", got)
	}
}

// TestGetPoetryInterpreterVersion_PEP621ConstraintFallback verifies that when a
// PEP 621 project declares requires-python but has NO .venv from which a
// concrete version can be read, the declared constraint is returned verbatim.
func TestGetPoetryInterpreterVersion_PEP621ConstraintFallback(t *testing.T) {
	envDir := t.TempDir()

	pyproject := `[project]
name = "modern-app"
requires-python = ">=3.10,<3.13"
`
	if err := os.WriteFile(filepath.Join(envDir, "pyproject.toml"), []byte(pyproject), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := getPoetryInterpreterVersion(envDir); got != ">=3.10,<3.13" {
		t.Errorf("getPoetryInterpreterVersion() = %q, want the requires-python constraint verbatim", got)
	}
}

// TestGetPoetryInterpreterVersion_LegacyStillWorks verifies the legacy Poetry
// 1.x form ([tool.poetry.dependencies] python = "^3.11") is still honoured when
// there is no .venv to read a concrete version from.
func TestGetPoetryInterpreterVersion_LegacyStillWorks(t *testing.T) {
	envDir := t.TempDir()

	pyproject := `[tool.poetry]
name = "legacy-app"

[tool.poetry.dependencies]
python = "^3.11"
requests = "^2.31.0"
`
	if err := os.WriteFile(filepath.Join(envDir, "pyproject.toml"), []byte(pyproject), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := getPoetryInterpreterVersion(envDir); got != "^3.11" {
		t.Errorf("getPoetryInterpreterVersion() = %q, want legacy ^3.11 constraint", got)
	}
}
