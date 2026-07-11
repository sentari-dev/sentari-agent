package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// condaScanner discovers conda environments by matching directories that
// contain a conda-meta subdirectory (the canonical conda env marker).
type condaScanner struct{}

func (condaScanner) EnvType() string { return EnvConda }

func (condaScanner) Match(dirPath, _ string) MatchResult {
	condaMeta := filepath.Join(dirPath, "conda-meta")
	info, err := os.Stat(condaMeta)
	if err != nil || !info.IsDir() {
		return MatchResult{}
	}
	return MatchResult{
		Matched:  true,
		Terminal: true, // don't descend into a conda env
		Env: Environment{
			EnvType: EnvConda,
			Path:    dirPath,
			Name:    filepath.Base(dirPath),
		},
	}
}

func (condaScanner) Scan(_ context.Context, env Environment) ([]PackageRecord, []ScanError) {
	packages, scanErrs := scanCondaEnvironment(env.Path)

	// Packages installed with `pip install` inside an activated conda env land
	// in the env's site-packages (lib/pythonX.Y/site-packages on unix,
	// Lib/site-packages on Windows), never in conda-meta — so
	// scanCondaEnvironment above can't see them.  This is extremely common in
	// the wild.  Reuse the pip site-packages parser over the same directory
	// and fold the results in.  Guard on findSitePackages first: a conda env
	// with no Python (e.g. an r-base-only env) has no site-packages, and we
	// don't want a spurious "site-packages not found" ScanError.
	if findSitePackages(env.Path) != "" {
		pipPkgs, pipErrs := scanPipEnvironment(env.Path)
		// Re-tag as conda so env-scoped downstream handling is unchanged.  The
		// records still carry the pip parser's site-packages InstallPath and
		// InstallerUser — that (rather than any new contract field) is how the
		// server tells a pip-origin package inside a conda env apart from a
		// conda-meta one.
		for i := range pipPkgs {
			pipPkgs[i].EnvType = EnvConda
		}
		// Dedup by PEP 503-normalized name; the conda-meta record wins when a
		// package is recorded in both sources.
		packages = mergeCondaPipPackages(packages, pipPkgs)
		scanErrs = append(scanErrs, pipErrs...)
	}

	return packages, scanErrs
}

// normalizePEP503 canonicalizes a Python project name per PEP 503: lowercase,
// with any run of "-", "_" or "." collapsed to a single "-".  Used to dedup a
// package that appears in both conda-meta and the env's pip site-packages
// (e.g. conda "Ruamel.yaml" vs pip "ruamel-yaml" is the same distribution).
func normalizePEP503(name string) string {
	var b strings.Builder
	prevSep := false
	for _, r := range strings.ToLower(name) {
		if r == '-' || r == '_' || r == '.' {
			if !prevSep {
				b.WriteByte('-')
				prevSep = true
			}
			continue
		}
		b.WriteRune(r)
		prevSep = false
	}
	return b.String()
}

// mergeCondaPipPackages folds pip-origin records into the conda-meta records.
//
// A package can legitimately appear in BOTH conda-meta and the env's pip
// site-packages under the same PEP 503-normalized name.  Two distinct cases
// hide behind that collision, and they need opposite handling:
//
//   - EQUAL versions — a true duplicate.  conda-meta and the on-disk
//     .dist-info agree, so the pip record carries no new information; drop it
//     and keep the conda-meta record.
//
//   - DIFFERING versions — conda-meta and the on-disk .dist-info disagree.
//     This happens both ways and we cannot know which is authoritative:
//     `pip install -U <pkg>` inside an activated conda env rewrites
//     site-packages + <pkg>.dist-info WITHOUT touching conda-meta (conda-meta
//     goes stale, .dist-info matches the files on disk), while the reverse — an
//     orphaned pip .dist-info later superseded by a `conda install` — leaves
//     conda-meta correct.  Guessing authority would silently hide the real
//     on-disk version from CVE correlation in one of the two cases.  So EMIT
//     BOTH records: they already differ by InstallPath (conda-meta json vs
//     site-packages .dist-info) and the pip record carries pip-origin markers,
//     so the server sees both versions and CVE correlation covers whichever is
//     actually on disk.
func mergeCondaPipPackages(condaPkgs, pipPkgs []PackageRecord) []PackageRecord {
	// PEP 503 name -> set of conda-meta versions recorded under that name.
	condaVersions := make(map[string]map[string]struct{}, len(condaPkgs))
	for _, p := range condaPkgs {
		key := normalizePEP503(p.Name)
		if condaVersions[key] == nil {
			condaVersions[key] = make(map[string]struct{}, 1)
		}
		condaVersions[key][p.Version] = struct{}{}
	}
	for _, p := range pipPkgs {
		key := normalizePEP503(p.Name)
		if vers, ok := condaVersions[key]; ok {
			if _, sameVersion := vers[p.Version]; sameVersion {
				continue // true duplicate: the conda-meta record already covers it
			}
			// Versions differ — keep both so the on-disk version is not hidden.
		}
		condaPkgs = append(condaPkgs, p)
	}
	return condaPkgs
}

func init() {
	Register(condaScanner{})
}

// condaPackageMetadata represents the structure of a conda package metadata file.
// Conda stores one JSON file per package in envs/<name>/conda-meta/.
type condaPackageMetadata struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// scanCondaEnvironment scans a conda environment for installed packages
// by reading JSON files from the conda-meta directory.
func scanCondaEnvironment(envPath string) ([]PackageRecord, []ScanError) {
	var packages []PackageRecord
	var scanErrs []ScanError

	condaMetaPath := filepath.Join(envPath, "conda-meta")

	// safeio.ReadDir (not os.ReadDir): conda-meta is a freshly-constructed
	// metadata directory conda always creates as a real dir — it is never
	// legitimately a symlink, so a symlinked conda-meta can only be an
	// attacker (with write to a compromised env) redirecting enumeration to
	// an arbitrary tree.  Refusing it here mirrors the symlink-refusing leaf
	// read in parseCondaPackageMetadata.  This does NOT regress a symlinked
	// conda ENVIRONMENT: Lstat only checks the conda-meta leaf, so an
	// ancestor envPath symlink is still followed normally.
	entries, err := safeio.ReadDir(condaMetaPath)
	if err != nil {
		scanErrs = append(scanErrs, ScanError{
			Path:      envPath,
			EnvType:   EnvConda,
			Error:     err.Error(),
			Timestamp: time.Now().UTC(),
		})
		return packages, scanErrs
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			pkg, err := parseCondaPackageMetadata(filepath.Join(condaMetaPath, entry.Name()), envPath)
			if err == nil {
				packages = append(packages, pkg)
			} else {
				scanErrs = append(scanErrs, ScanError{
					Path:      filepath.Join(condaMetaPath, entry.Name()),
					EnvType:   EnvConda,
					Error:     err.Error(),
					Timestamp: time.Now().UTC(),
				})
			}
		}
	}

	// Detect Python version from the conda-meta "python" package — no binary invocation.
	interpreterVersion := getCondaInterpreterVersion(condaMetaPath, entries)
	for i := range packages {
		packages[i].EnvType = EnvConda
		packages[i].Environment = envPath
		packages[i].InterpreterVersion = interpreterVersion
	}

	return packages, scanErrs
}

// parseCondaPackageMetadata parses a conda package metadata JSON file.
// Reads through safeio so a symlinked conda-meta/*.json (unusual, but
// possible in a compromised env) can't exfiltrate the symlink target.
func parseCondaPackageMetadata(metadataPath, envPath string) (PackageRecord, error) {
	data, err := safeio.ReadFile(metadataPath, maxCondaMetadataSize)
	if err != nil {
		return PackageRecord{}, err
	}

	var metadata condaPackageMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return PackageRecord{}, err
	}

	// Guard against a valid-JSON-but-identity-less metadata file (e.g. "{}").
	// Without a name there is no package to correlate on the wire, so emitting
	// one would produce a ghost record with Name=""/Version="".  Report it as a
	// ScanError instead, matching npm/nuget behaviour (malformed file surfaced,
	// not emitted as a package).  A name with an empty version is still a real
	// package (keyed on name), so only an empty name is the trigger.
	if metadata.Name == "" {
		return PackageRecord{}, fmt.Errorf("conda-meta file %q has no package name", metadataPath)
	}

	raw, spdx, tier := ExtractLicenseFromCondaJSON(data)

	return PackageRecord{
		Name:        metadata.Name,
		Version:     metadata.Version,
		InstallPath: metadataPath,
		InstallDate: getFileModTime(metadataPath),
		LicenseRaw:  raw,
		LicenseSPDX: spdx,
		LicenseTier: tier,
	}, nil
}

// getCondaInterpreterVersion extracts the Python version from the conda-meta
// directory by finding the python-*.json metadata file. This avoids invoking
// any binary — the conda metadata already records the exact version.
func getCondaInterpreterVersion(condaMetaPath string, entries []os.DirEntry) string {
	for _, entry := range entries {
		name := entry.Name()
		// conda-meta contains files like "python-3.11.7-h955ad1f_0.json".
		if !strings.HasPrefix(name, "python-") || !strings.HasSuffix(name, ".json") {
			continue
		}
		// Quick path: extract version from filename.
		// Format: python-<version>-<build>.json
		trimmed := strings.TrimPrefix(name, "python-")
		trimmed = strings.TrimSuffix(trimmed, ".json")
		// The char after the "python-" prefix must be a digit: the
		// interpreter package is always "python-<version>-…", so a
		// non-digit here means a differently-named package that merely
		// shares the prefix ("python-dateutil-2.8.2", "python-json-logger-…").
		// Skip those and keep scanning for the real interpreter record.
		if trimmed == "" || trimmed[0] < '0' || trimmed[0] > '9' {
			continue
		}
		// Split on "-" — first part is version, rest is build string.
		if idx := strings.Index(trimmed, "-"); idx > 0 {
			return trimmed[:idx]
		}
		// Fallback: try reading the JSON file for exact version.
		data, err := safeio.ReadFile(filepath.Join(condaMetaPath, name), maxCondaMetadataSize)
		if err == nil {
			var meta condaPackageMetadata
			if json.Unmarshal(data, &meta) == nil && meta.Version != "" {
				return meta.Version
			}
		}
		return trimmed
	}
	return "unknown"
}
