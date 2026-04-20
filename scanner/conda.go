package scanner

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
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
	return scanCondaEnvironment(env.Path)
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
	var errors []ScanError

	condaMetaPath := filepath.Join(envPath, "conda-meta")

	entries, err := os.ReadDir(condaMetaPath)
	if err != nil {
		errors = append(errors, ScanError{
			Path:      envPath,
			EnvType:   EnvConda,
			Error:     err.Error(),
			Timestamp: time.Now().UTC(),
		})
		return packages, errors
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			pkg, err := parseCondaPackageMetadata(filepath.Join(condaMetaPath, entry.Name()), envPath)
			if err == nil {
				packages = append(packages, pkg)
			} else {
				errors = append(errors, ScanError{
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

	return packages, errors
}

// maxMetadataFileSize is the upper bound for metadata files the scanner will
// read into memory. Files larger than this are skipped to prevent OOM from
// maliciously crafted or corrupted metadata.
const maxMetadataFileSize = 10 << 20 // 10 MiB

// parseCondaPackageMetadata parses a conda package metadata JSON file.
func parseCondaPackageMetadata(metadataPath, envPath string) (PackageRecord, error) {
	data, err := readFileBounded(metadataPath, maxMetadataFileSize)
	if err != nil {
		return PackageRecord{}, err
	}

	var metadata condaPackageMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return PackageRecord{}, err
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
		// conda-meta contains files like "python-3.11.7-h955ad1f_0.json"
		if strings.HasPrefix(name, "python-") && strings.HasSuffix(name, ".json") {
			// Quick path: extract version from filename.
			// Format: python-<version>-<build>.json
			trimmed := strings.TrimPrefix(name, "python-")
			trimmed = strings.TrimSuffix(trimmed, ".json")
			// Split on "-" — first part is version, rest is build string.
			if idx := strings.Index(trimmed, "-"); idx > 0 {
				return trimmed[:idx]
			}
			// Fallback: try reading the JSON file for exact version.
			data, err := readFileBounded(filepath.Join(condaMetaPath, name), maxMetadataFileSize)
			if err == nil {
				var meta condaPackageMetadata
				if json.Unmarshal(data, &meta) == nil && meta.Version != "" {
					return meta.Version
				}
			}
			return trimmed
		}
	}
	return "unknown"
}
