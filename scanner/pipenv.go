package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// pipfileLockData represents the top-level structure of a Pipfile.lock.
type pipfileLockData struct {
	Meta    pipfileLockMeta                `json:"_meta"`
	Default map[string]pipfileLockEntry    `json:"default"`
	Develop map[string]pipfileLockEntry    `json:"develop"`
}

// pipfileLockMeta holds the _meta section of Pipfile.lock.
type pipfileLockMeta struct {
	Requires pipfileLockRequires `json:"requires"`
}

// pipfileLockRequires holds the python version constraint.
type pipfileLockRequires struct {
	PythonVersion string `json:"python_version"`
	PythonFullVersion string `json:"python_full_version"`
}

// pipfileLockEntry represents a single package entry in Pipfile.lock.
type pipfileLockEntry struct {
	Version string `json:"version"`
}

// scanPipenvEnvironment scans a pipenv environment for dependencies from Pipfile.lock.
// It parses the JSON lock file directly — no pipenv binary is invoked.
func scanPipenvEnvironment(envPath string) ([]PackageRecord, []ScanError) {
	var packages []PackageRecord
	var errors []ScanError

	pipfileLockPath := filepath.Join(envPath, "Pipfile.lock")

	data, err := readFileBounded(pipfileLockPath, maxMetadataFileSize)
	if err != nil {
		errors = append(errors, ScanError{
			Path:      envPath,
			EnvType:   EnvPipenv,
			Error:     err.Error(),
			Timestamp: time.Now().UTC(),
		})
		return packages, errors
	}

	var lockData pipfileLockData
	if err := json.Unmarshal(data, &lockData); err != nil {
		errors = append(errors, ScanError{
			Path:      pipfileLockPath,
			EnvType:   EnvPipenv,
			Error:     err.Error(),
			Timestamp: time.Now().UTC(),
		})
		return packages, errors
	}

	lockModTime := getFileModTime(pipfileLockPath)

	// Locate site-packages for license metadata lookup.
	// Pipenv may use a .venv in the project directory.
	sitePackagesDir := findSitePackages(filepath.Join(envPath, ".venv"))

	// Process default + develop packages.
	addPackages := func(entries map[string]pipfileLockEntry) {
		for name, entry := range entries {
			version := stripVersionPrefix(entry.Version)
			pkg := PackageRecord{
				Name:        name,
				Version:     version,
				InstallPath: pipfileLockPath,
				InstallDate: lockModTime,
				EnvType:     EnvPipenv,
				Environment: envPath,
			}

			// Try to extract license from installed METADATA in site-packages.
			if sitePackagesDir != "" {
				metadataPath := filepath.Join(sitePackagesDir, name+"-"+version+".dist-info", "METADATA")
				if metaBytes, err := os.ReadFile(metadataPath); err == nil {
					raw, spdx, tier := ExtractLicenseFromMetadata(string(metaBytes))
					pkg.LicenseRaw = raw
					pkg.LicenseSPDX = spdx
					pkg.LicenseTier = tier
				}
			}

			packages = append(packages, pkg)
		}
	}

	addPackages(lockData.Default)
	addPackages(lockData.Develop)

	// Extract interpreter version from _meta.requires — no binary invocation needed.
	interpreterVersion := getPipenvInterpreterVersion(lockData)
	for i := range packages {
		packages[i].InterpreterVersion = interpreterVersion
	}

	return packages, errors
}

// stripVersionPrefix removes leading == from pipenv version strings.
// "==1.2.3" → "1.2.3", ">=1.0" → ">=1.0" (only strips exact match prefix).
func stripVersionPrefix(version string) string {
	if strings.HasPrefix(version, "==") {
		return version[2:]
	}
	return version
}

// getPipenvInterpreterVersion extracts the Python version from the already-parsed
// Pipfile.lock _meta section. This is the most reliable source — it records the
// exact Python version used when the lock file was generated.
func getPipenvInterpreterVersion(lockData pipfileLockData) string {
	// Prefer full version (e.g., "3.11.7") over short version (e.g., "3.11").
	if v := lockData.Meta.Requires.PythonFullVersion; v != "" {
		return v
	}
	if v := lockData.Meta.Requires.PythonVersion; v != "" {
		return v
	}
	return "unknown"
}
