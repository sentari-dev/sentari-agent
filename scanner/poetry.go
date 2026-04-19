package scanner

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// scanPoetryEnvironment parses a poetry.lock file to extract package metadata.
// poetry.lock uses TOML format with [[package]] array-of-tables entries.
// We use a lightweight line-based parser instead of a full TOML library to
// avoid the heavyweight go-toml dependency for a simple extraction task.
func scanPoetryEnvironment(envPath string) ([]PackageRecord, []ScanError) {
	var packages []PackageRecord
	var errors []ScanError

	poetryLockPath := filepath.Join(envPath, "poetry.lock")

	file, err := os.Open(poetryLockPath)
	if err != nil {
		errors = append(errors, ScanError{
			Path:      envPath,
			EnvType:   EnvPoetry,
			Error:     err.Error(),
			Timestamp: time.Now().UTC(),
		})
		return packages, errors
	}
	defer file.Close()

	lockModTime := getFileModTime(poetryLockPath)
	interpreterVersion := getPoetryInterpreterVersion(envPath)

	// Locate site-packages for license metadata lookup.
	// Poetry typically uses a .venv in the project directory.
	sitePackagesDir := findSitePackages(filepath.Join(envPath, ".venv"))

	// Parse [[package]] sections from the TOML file.
	// Each section has name = "..." and version = "..." lines.
	var inPackage bool
	var currentName, currentVersion string

	flushPackage := func() {
		if currentName != "" && currentVersion != "" {
			pkg := PackageRecord{
				Name:               currentName,
				Version:            currentVersion,
				InstallPath:        envPath,
				EnvType:            EnvPoetry,
				InterpreterVersion: interpreterVersion,
				InstallDate:        lockModTime,
				Environment:        envPath,
			}

			// Try to extract license from installed METADATA in site-packages.
			if sitePackagesDir != "" {
				metadataPath := filepath.Join(sitePackagesDir, currentName+"-"+currentVersion+".dist-info", "METADATA")
				if metaBytes, err := os.ReadFile(metadataPath); err == nil {
					raw, spdx, tier := ExtractLicenseFromMetadata(string(metaBytes))
					pkg.LicenseRaw = raw
					pkg.LicenseSPDX = spdx
					pkg.LicenseTier = tier
				}
			}

			packages = append(packages, pkg)
		}
		currentName = ""
		currentVersion = ""
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// New [[package]] section.
		if line == "[[package]]" {
			flushPackage()
			inPackage = true
			continue
		}

		// New section that isn't [[package]] — end current package.
		if strings.HasPrefix(line, "[") {
			flushPackage()
			inPackage = false
			continue
		}

		if !inPackage {
			continue
		}

		// Parse key = "value" lines within a [[package]] section.
		key, value, ok := parseTomlKeyValue(line)
		if !ok {
			continue
		}

		switch key {
		case "name":
			currentName = value
		case "version":
			currentVersion = value
		}
	}

	// Flush the last package.
	flushPackage()

	if err := scanner.Err(); err != nil {
		errors = append(errors, ScanError{
			Path:      poetryLockPath,
			EnvType:   EnvPoetry,
			Error:     err.Error(),
			Timestamp: time.Now().UTC(),
		})
	}

	return packages, errors
}

// parseTomlKeyValue extracts a key and unquoted string value from a TOML line.
// Returns ("", "", false) for lines that aren't simple string key-value pairs.
func parseTomlKeyValue(line string) (string, string, bool) {
	// Skip comments and empty lines.
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}

	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}

	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	// We only care about quoted string values (double or single quotes).
	if len(value) >= 2 {
		if (value[0] == '"' && value[len(value)-1] == '"') ||
			(value[0] == '\'' && value[len(value)-1] == '\'') {
			return key, value[1 : len(value)-1], true
		}
	}

	return "", "", false
}

// getPoetryInterpreterVersion reads the Python version constraint from
// pyproject.toml if available, otherwise checks for a local .venv.
func getPoetryInterpreterVersion(envPath string) string {
	// Try to read pyproject.toml for the python version constraint.
	pyprojectPath := filepath.Join(envPath, "pyproject.toml")
	if file, err := os.Open(pyprojectPath); err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		inDeps := false
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())

			if line == "[tool.poetry.dependencies]" {
				inDeps = true
				continue
			}
			if strings.HasPrefix(line, "[") {
				inDeps = false
				continue
			}
			if inDeps {
				key, value, ok := parseTomlKeyValue(line)
				if ok && key == "python" {
					return value
				}
			}
		}
	}

	// Check for a .venv directory as a fallback indicator.
	venvPath := filepath.Join(envPath, ".venv")
	candidates := []string{
		filepath.Join(venvPath, "bin", "python"),
		filepath.Join(venvPath, "bin", "python3"),
		filepath.Join(venvPath, "Scripts", "python.exe"),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return "3.x (poetry venv)"
		}
	}

	return "unknown"
}
