package scanner

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// poetryScanner discovers poetry projects by matching directories that
// contain a poetry.lock file.  Non-terminal: a monorepo can have a
// top-level poetry.lock and per-subproject envs worth descending into.
type poetryScanner struct{}

func (poetryScanner) EnvType() string { return EnvPoetry }

func (poetryScanner) Match(dirPath, base string) MatchResult {
	poetryLock := filepath.Join(dirPath, "poetry.lock")
	if _, err := os.Stat(poetryLock); err != nil {
		return MatchResult{}
	}
	return MatchResult{
		Matched:  true,
		Terminal: false,
		Env: Environment{
			EnvType: EnvPoetry,
			Path:    dirPath,
			Name:    base,
		},
	}
}

func (poetryScanner) Scan(_ context.Context, env Environment) ([]PackageRecord, []ScanError) {
	return scanPoetryEnvironment(env.Path)
}

func init() {
	Register(poetryScanner{})
}

// scanPoetryEnvironment parses a poetry.lock file to extract package metadata.
// poetry.lock uses TOML format with [[package]] array-of-tables entries.
// We use a lightweight line-based parser instead of a full TOML library to
// avoid the heavyweight go-toml dependency for a simple extraction task.
func scanPoetryEnvironment(envPath string) ([]PackageRecord, []ScanError) {
	var packages []PackageRecord
	var scanErrs []ScanError

	poetryLockPath := filepath.Join(envPath, "poetry.lock")

	// Bounded + symlink-refusing read.  A malicious monorepo could
	// plant `poetry.lock -> /etc/shadow` inside a directory the
	// scanner walks into; safeio refuses the follow.
	data, err := safeio.ReadFile(poetryLockPath, maxLockFileSize)
	if err != nil {
		scanErrs = append(scanErrs, ScanError{
			Path:      envPath,
			EnvType:   EnvPoetry,
			Error:     err.Error(),
			Timestamp: time.Now().UTC(),
		})
		return packages, scanErrs
	}

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
				// Default to "unknown" (matching every other scanner) when
				// no .venv METADATA is present to classify the license — an
				// empty string would be silently ingested as "no license
				// info" rather than "unclassified" server-side.
				LicenseTier: "unknown",
			}

			// Try to extract license from installed METADATA in site-packages.
			// The dist-info dir name is the wheel-normalized project name, not
			// the raw poetry.lock name (see findDistInfoMetadata).
			if metaBytes := findDistInfoMetadata(sitePackagesDir, currentName, currentVersion); metaBytes != nil {
				raw, spdx, tier := ExtractLicenseFromMetadata(string(metaBytes))
				pkg.LicenseRaw = raw
				pkg.LicenseSPDX = spdx
				pkg.LicenseTier = tier
			}

			packages = append(packages, pkg)
		}
		currentName = ""
		currentVersion = ""
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
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
		scanErrs = append(scanErrs, ScanError{
			Path:      poetryLockPath,
			EnvType:   EnvPoetry,
			Error:     err.Error(),
			Timestamp: time.Now().UTC(),
		})
	}

	return packages, scanErrs
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

// normalizeDistInfoName normalizes a project name into the form used for
// wheel .dist-info directory names: lowercased, with runs of [-_.]
// collapsed to a single underscore (per the binary-distribution spec).
// e.g. "typing-extensions" → "typing_extensions", "ruamel.yaml" →
// "ruamel_yaml", "Jinja2" → "jinja2". Without this, a lock-file name like
// "typing-extensions" never matches "typing_extensions-4.9.0.dist-info" on
// disk and the package is misclassified as license tier "unknown".
func normalizeDistInfoName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	prevSep := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('_')
				prevSep = true
			}
			continue
		}
		b.WriteRune(r)
		prevSep = false
	}
	return b.String()
}

// findDistInfoMetadata locates and reads the METADATA file for a package
// installed under sitePackagesDir. Wheel install directories are named
// "<normalized>-<version>.dist-info" where <normalized> is the project name
// run through normalizeDistInfoName — so "typing-extensions" is stored as
// "typing_extensions-4.9.0.dist-info", not "typing-extensions-...". We first
// try the direct normalized path (the common case), then fall back to a
// case-insensitive scan of the directory entries. Returns nil if no matching
// METADATA can be read. Shared by the poetry and pipenv scanners.
func findDistInfoMetadata(sitePackagesDir, name, version string) []byte {
	if sitePackagesDir == "" {
		return nil
	}

	distInfo := normalizeDistInfoName(name) + "-" + version + ".dist-info"

	// Direct hit — the common case.
	metadataPath := filepath.Join(sitePackagesDir, distInfo, "METADATA")
	if data, err := safeio.ReadFile(metadataPath, maxPipMetadataSize); err == nil {
		return data
	}

	// Fall back to a case-insensitive scan of the site-packages entries;
	// some tools preserve project-name casing on case-sensitive filesystems.
	entries, err := os.ReadDir(sitePackagesDir)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		if strings.EqualFold(entry.Name(), distInfo) {
			p := filepath.Join(sitePackagesDir, entry.Name(), "METADATA")
			if data, err := safeio.ReadFile(p, maxPipMetadataSize); err == nil {
				return data
			}
		}
	}
	return nil
}

// getPoetryInterpreterVersion determines the Python interpreter version for a
// poetry project without invoking any binary.  It understands both interpreter
// declarations:
//
//   - legacy Poetry 1.x:  [tool.poetry.dependencies] python = "^3.11"
//   - PEP 621 / Poetry 2.x: [project] requires-python = ">=3.9"
//
// Both of those are *constraints* (what the project accepts), not the concrete
// interpreter that is installed.  When the project has a local .venv we prefer
// the concrete version read from its pyvenv.cfg / lib layout
// (detectInterpreterVersion, which now carries the version_info fallback) over
// the declared constraint.  Only when no concrete version can be read do we
// fall back to the declared constraint verbatim.
func getPoetryInterpreterVersion(envPath string) string {
	constraint := parsePyprojectPythonConstraint(envPath)

	venvPath := filepath.Join(envPath, ".venv")

	// Prefer a concrete interpreter version from the project's .venv over a
	// bare constraint.  detectInterpreterVersion reads pyvenv.cfg
	// (version / version_info) and the lib/pythonX.Y directory name.
	if v := detectInterpreterVersion(venvPath); v != "unknown" && v != "" {
		return v
	}

	// No concrete venv version — fall back to the declared constraint.
	if constraint != "" {
		return constraint
	}

	// Last resort: a .venv exists but carried no readable version.
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

// parsePyprojectPythonConstraint extracts the declared Python version
// constraint from pyproject.toml, understanding both the legacy Poetry form
// ([tool.poetry.dependencies] python = "...") and the PEP 621 form
// ([project] requires-python = "..."). The legacy poetry constraint wins when
// both are present (a Poetry 1.x project that also carries a [project] table).
// Returns "" when neither is declared or the file cannot be read.
func parsePyprojectPythonConstraint(envPath string) string {
	pyprojectPath := filepath.Join(envPath, "pyproject.toml")
	data, err := safeio.ReadFile(pyprojectPath, maxPyprojectSize)
	if err != nil {
		return ""
	}

	var legacyPython, requiresPython string
	section := ""
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "[") {
			section = line
			continue
		}
		key, value, ok := parseTomlKeyValue(line)
		if !ok {
			continue
		}
		switch section {
		case "[tool.poetry.dependencies]":
			if key == "python" {
				legacyPython = value
			}
		case "[project]":
			if key == "requires-python" {
				requiresPython = value
			}
		}
	}

	if legacyPython != "" {
		return legacyPython
	}
	return requiresPython
}
