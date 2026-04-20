package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// pipScanner discovers global pip installs by matching site-packages
// directories during the shared walk.  Venvs have their own scanner
// (venvScanner) because they also need dangling-symlink detection and
// a different EnvType tag on emitted packages.
type pipScanner struct{}

func (pipScanner) EnvType() string { return EnvPip }

func (pipScanner) Match(dirPath, base string) MatchResult {
	if base != "site-packages" {
		return MatchResult{}
	}
	return MatchResult{
		Matched:  true,
		Terminal: true, // don't descend into site-packages itself
		Env: Environment{
			EnvType: EnvPip,
			Path:    dirPath,
			Name:    "global",
		},
	}
}

func (pipScanner) Scan(_ context.Context, env Environment) ([]PackageRecord, []ScanError) {
	return scanPipEnvironment(env.Path)
}

// venvScanner discovers virtualenvs by matching pyvenv.cfg and rejects
// dangling venvs (whose base interpreter has been uninstalled) with a
// warning instead of queueing them.  Venv-tagged packages share the pip
// parser but are re-tagged with EnvVenv in Scan().
type venvScanner struct{}

func (venvScanner) EnvType() string { return EnvVenv }

func (venvScanner) Match(dirPath, base string) MatchResult {
	pyvenvCfg := filepath.Join(dirPath, "pyvenv.cfg")
	if _, err := os.Stat(pyvenvCfg); err != nil {
		return MatchResult{}
	}
	if reason := isVenvDangling(dirPath, pyvenvCfg); reason != "" {
		return MatchResult{
			Terminal: true,
			Warning: &ScanError{
				Path:      dirPath,
				EnvType:   EnvVenv,
				Error:     reason,
				Timestamp: time.Now().UTC(),
			},
		}
	}
	return MatchResult{
		Matched:  true,
		Terminal: true, // don't descend into a venv
		Env: Environment{
			EnvType: EnvVenv,
			Path:    dirPath,
			Name:    base,
		},
	}
}

func (venvScanner) Scan(_ context.Context, env Environment) ([]PackageRecord, []ScanError) {
	pkgs, errs := scanPipEnvironment(env.Path)
	// scanPipEnvironment tags every record as EnvPip; override to EnvVenv
	// so the server distinguishes global pip from venv-scoped packages.
	for i := range pkgs {
		pkgs[i].EnvType = EnvVenv
	}
	return pkgs, errs
}

func init() {
	Register(pipScanner{})
	Register(venvScanner{})
}

// scanPipEnvironment scans a pip/venv environment for installed packages
// by parsing .dist-info/METADATA and .egg-info/PKG-INFO files.
func scanPipEnvironment(envPath string) ([]PackageRecord, []ScanError) {
	var packages []PackageRecord
	var errors []ScanError

	// Locate the site-packages directory.
	sitePackagesPath := findSitePackages(envPath)
	if sitePackagesPath == "" {
		errors = append(errors, ScanError{
			Path:      envPath,
			EnvType:   EnvPip,
			Error:     "site-packages not found",
			Timestamp: time.Now().UTC(),
		})
		return packages, errors
	}

	entries, err := os.ReadDir(sitePackagesPath)
	if err != nil {
		errors = append(errors, ScanError{
			Path:      sitePackagesPath,
			EnvType:   EnvPip,
			Error:     err.Error(),
			Timestamp: time.Now().UTC(),
		})
		return packages, errors
	}

	for _, entry := range entries {
		name := entry.Name()

		if entry.IsDir() {
			if strings.HasSuffix(name, ".dist-info") {
				pkg, err := parseDistInfo(filepath.Join(sitePackagesPath, name), envPath)
				if err == nil {
					packages = append(packages, pkg)
				} else {
					errors = append(errors, ScanError{
						Path:      filepath.Join(sitePackagesPath, name),
						EnvType:   EnvPip,
						Error:     err.Error(),
						Timestamp: time.Now().UTC(),
					})
				}
				continue
			}

			if strings.HasSuffix(name, ".egg-info") {
				pkg, err := parseEggInfo(filepath.Join(sitePackagesPath, name), envPath)
				if err == nil {
					packages = append(packages, pkg)
				} else {
					errors = append(errors, ScanError{
						Path:      filepath.Join(sitePackagesPath, name),
						EnvType:   EnvPip,
						Error:     err.Error(),
						Timestamp: time.Now().UTC(),
					})
				}
			}
			continue
		}

		// .egg-link files are regular files (not directories) created by
		// legacy editable installs (pip install -e with older setuptools).
		if strings.HasSuffix(name, ".egg-link") {
			pkg, err := parseEggLink(filepath.Join(sitePackagesPath, name), sitePackagesPath)
			if err == nil {
				packages = append(packages, pkg)
			} else {
				errors = append(errors, ScanError{
					Path:      filepath.Join(sitePackagesPath, name),
					EnvType:   EnvPip,
					Error:     err.Error(),
					Timestamp: time.Now().UTC(),
				})
			}
		}
	}

	// Determine interpreter version from filesystem (never invoke python binary).
	interpreterVersion := detectInterpreterVersion(envPath)

	for i := range packages {
		packages[i].EnvType = EnvPip
		packages[i].Environment = envPath
		packages[i].InterpreterVersion = interpreterVersion
	}

	return packages, errors
}

// findSitePackages locates the site-packages directory inside an environment.
// It handles both Unix (lib/pythonX.Y/site-packages) and Windows (Lib/site-packages).
func findSitePackages(envPath string) string {
	// If the path itself IS site-packages, use it directly.
	if filepath.Base(envPath) == "site-packages" {
		return envPath
	}

	// Unix layout: lib/pythonX.Y/site-packages
	libDir := filepath.Join(envPath, "lib")
	if entries, err := os.ReadDir(libDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), "python") {
				candidate := filepath.Join(libDir, entry.Name(), "site-packages")
				if info, err := os.Stat(candidate); err == nil && info.IsDir() {
					return candidate
				}
			}
		}
	}

	// Windows layout: Lib/site-packages
	candidate := filepath.Join(envPath, "Lib", "site-packages")
	if info, err := os.Stat(candidate); err == nil && info.IsDir() {
		return candidate
	}

	return ""
}

// detectInterpreterVersion determines the Python version without invoking any binary.
// It reads pyvenv.cfg (contains "version = 3.11.0") or infers from the
// lib/pythonX.Y directory name.
func detectInterpreterVersion(envPath string) string {
	// Strategy 1: Parse pyvenv.cfg — most reliable for venvs.
	// Read the whole file via safeio (symlink-refusing, size-capped)
	// then scan it in memory; a plain os.Open would silently follow
	// a pyvenv.cfg -> /etc/shadow symlink planted by an unprivileged
	// user inside a venv directory they control.
	pyvenvCfg := filepath.Join(envPath, "pyvenv.cfg")
	if data, err := safeio.ReadFile(pyvenvCfg, maxPyvenvCfgSize); err == nil {
		s := bufio.NewScanner(bytes.NewReader(data))
		for s.Scan() {
			line := s.Text()
			// pyvenv.cfg contains "version = 3.11.0" or "version_info = 3.11.0.final.0"
			if strings.HasPrefix(line, "version ") {
				parts := strings.SplitN(line, "=", 2)
				if len(parts) == 2 {
					v := strings.TrimSpace(parts[1])
					if v != "" {
						return v
					}
				}
			}
		}
	}

	// Strategy 2: Infer from lib/pythonX.Y directory name.
	libDir := filepath.Join(envPath, "lib")
	if entries, err := os.ReadDir(libDir); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() && strings.HasPrefix(name, "python") {
				// "python3.11" → "3.11"
				ver := strings.TrimPrefix(name, "python")
				if ver != "" {
					return ver
				}
			}
		}
	}

	// Strategy 3: Check for python version file in Windows Lib directory.
	libDir = filepath.Join(envPath, "Lib")
	if entries, err := os.ReadDir(libDir); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() && strings.HasPrefix(name, "python") {
				return strings.TrimPrefix(name, "python")
			}
		}
	}

	return "unknown"
}

// parseDistInfo parses METADATA file from a .dist-info directory.
// The METADATA file is an RFC 822-style file with Name: and Version:
// headers.  Read via safeio — a malicious site-packages entry that
// planted a METADATA symlink to /etc/shadow would otherwise end up in
// the scan payload we upload.  We read once and scan the bytes in-
// memory for both header extraction and license parsing.
func parseDistInfo(distInfoPath, envPath string) (PackageRecord, error) {
	metadataPath := filepath.Join(distInfoPath, "METADATA")
	data, err := safeio.ReadFile(metadataPath, maxPipMetadataSize)
	if err != nil {
		return PackageRecord{}, err
	}

	pkg := PackageRecord{
		InstallPath:   distInfoPath,
		InstallDate:   getFileModTime(distInfoPath),
		InstallerUser: getInstallerUser(distInfoPath),
	}

	s := bufio.NewScanner(bytes.NewReader(data))
	for s.Scan() {
		line := s.Text()

		if strings.HasPrefix(line, "Name: ") {
			pkg.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name: "))
		} else if strings.HasPrefix(line, "Version: ") {
			pkg.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
		}

		// Once we have both, no need to read further.
		if pkg.Name != "" && pkg.Version != "" {
			break
		}

		// METADATA headers end at the first blank line — stop early.
		if line == "" {
			break
		}
	}

	if err := s.Err(); err != nil {
		return PackageRecord{}, err
	}

	// Fallback: extract name from directory name if METADATA is incomplete.
	if pkg.Name == "" {
		base := filepath.Base(distInfoPath)
		base = strings.TrimSuffix(base, ".dist-info")
		if idx := strings.LastIndex(base, "-"); idx > 0 {
			pkg.Name = base[:idx]
			if pkg.Version == "" {
				pkg.Version = base[idx+1:]
			}
		} else {
			pkg.Name = base
		}
	}

	// Extract license info from the same bytes we already have.
	raw, spdx, tier := ExtractLicenseFromMetadata(string(data))
	pkg.LicenseRaw = raw
	pkg.LicenseSPDX = spdx
	pkg.LicenseTier = tier

	return pkg, nil
}

// parseEggInfo parses PKG-INFO file from a .egg-info directory.
// Same safeio treatment as parseDistInfo — single read, scan bytes
// in-memory for both header and license extraction.
func parseEggInfo(eggInfoPath, envPath string) (PackageRecord, error) {
	pkgInfoPath := filepath.Join(eggInfoPath, "PKG-INFO")
	data, err := safeio.ReadFile(pkgInfoPath, maxPipMetadataSize)
	if err != nil {
		return PackageRecord{}, err
	}

	pkg := PackageRecord{
		InstallPath:   eggInfoPath,
		InstallDate:   getFileModTime(eggInfoPath),
		InstallerUser: getInstallerUser(eggInfoPath),
	}

	s := bufio.NewScanner(bytes.NewReader(data))
	for s.Scan() {
		line := s.Text()

		if strings.HasPrefix(line, "Name: ") {
			pkg.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name: "))
		} else if strings.HasPrefix(line, "Version: ") {
			pkg.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
		}

		if pkg.Name != "" && pkg.Version != "" {
			break
		}

		if line == "" {
			break
		}
	}

	if err := s.Err(); err != nil {
		return PackageRecord{}, err
	}

	if pkg.Name == "" {
		base := filepath.Base(eggInfoPath)
		base = strings.TrimSuffix(base, ".egg-info")
		if idx := strings.LastIndex(base, "-"); idx > 0 {
			pkg.Name = base[:idx]
			if pkg.Version == "" {
				pkg.Version = base[idx+1:]
			}
		} else {
			pkg.Name = base
		}
	}

	// Extract license info from the bytes we already have.
	{
		raw, spdx, tier := ExtractLicenseFromMetadata(string(data))
		pkg.LicenseRaw = raw
		pkg.LicenseSPDX = spdx
		pkg.LicenseTier = tier
	}

	return pkg, nil
}

// parseEggLink parses a legacy .egg-link file from site-packages.
// An egg-link is a plain text file where the first line is the path to the
// source directory of an editable install (pip install -e). The package name
// is extracted from the filename, and the version from PKG-INFO in the linked
// source directory if available.
func parseEggLink(eggLinkPath, sitePackagesPath string) (PackageRecord, error) {
	data, err := safeio.ReadFile(eggLinkPath, maxEggLinkSize)
	if err != nil {
		return PackageRecord{}, err
	}

	lines := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return PackageRecord{}, fmt.Errorf("empty egg-link file: %s", eggLinkPath)
	}

	srcDir := strings.TrimSpace(lines[0])
	// egg-link paths may be relative to site-packages.
	if !filepath.IsAbs(srcDir) {
		srcDir = filepath.Join(sitePackagesPath, srcDir)
	}

	// Extract package name from filename: my-project.egg-link -> my-project
	baseName := filepath.Base(eggLinkPath)
	pkgName := strings.TrimSuffix(baseName, ".egg-link")

	pkg := PackageRecord{
		Name:        pkgName,
		Version:     "unknown",
		InstallPath: srcDir,
		InstallDate: getFileModTime(eggLinkPath),
	}

	// Try to find version from PKG-INFO in an .egg-info dir inside srcDir.
	if entries, err := os.ReadDir(srcDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && strings.HasSuffix(entry.Name(), ".egg-info") {
				if parsed, err := parseEggInfo(filepath.Join(srcDir, entry.Name()), sitePackagesPath); err == nil {
					pkg.Name = parsed.Name
					pkg.Version = parsed.Version
				}
				break
			}
		}
	}

	return pkg, nil
}

// getFileModTime returns the modification time of a file as an RFC 3339 string.
func getFileModTime(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return info.ModTime().UTC().Format(time.RFC3339)
}

// getInstallerUser returns the OS owner of the file at the given path.
// Delegates to the platform-specific getFileOwner in owner_{unix,windows}.go.
func getInstallerUser(path string) string {
	return getFileOwner(path)
}
