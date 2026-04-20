// Package scanner detects all Python environments on a device and extracts
// package metadata. It is the core of the sentari-agent and has zero network
// dependencies — it only reads the local filesystem.
package scanner

import (
	"time"
)

// Per-file-type size caps.  Every metadata parse must go through
// scanner/safeio.ReadFile (symlink-refusing) with one of these as the
// limit.  Caps reflect the realistic p99 size of each format in the
// wild; a malicious package cannot force us to read a larger file.
const (
	// METADATA / PKG-INFO — RFC 822-style package metadata.
	// Real-world files are usually <50 KiB; 1 MiB is generous.
	maxPipMetadataSize int64 = 1 << 20

	// conda-meta/*.json — package manifest.  10 MiB retained from
	// the pre-safeio constant because some conda packages ship
	// very large dependency graphs.
	maxCondaMetadataSize int64 = 10 << 20

	// Pipfile.lock / poetry.lock — lockfiles.  4 MiB covers even
	// very large monorepo dependency graphs.
	maxLockFileSize int64 = 4 << 20

	// pyproject.toml — poetry scanner reads this for interpreter
	// version.  Small config file.
	maxPyprojectSize int64 = 1 << 20

	// /var/lib/dpkg/status — Debian package list.  Can be large
	// on systems with thousands of packages; 64 MiB is conservative.
	maxDpkgStatusSize int64 = 64 << 20

	// /usr/share/doc/<pkg>/copyright — Debian copyright file.  This
	// is the primary symlink-exfil target and must stay small to
	// bound the damage of any bypass.
	maxDebCopyrightSize int64 = 4 << 20

	// pyvenv.cfg — tiny ini-style config file.
	maxPyvenvCfgSize int64 = 64 << 10

	// .egg-link files — legacy editable-install pointers.
	maxEggLinkSize int64 = 64 << 10
)

// EnvType identifies the type of Python environment a package was found in.
type EnvType = string

const (
	EnvPip       EnvType = "pip"
	EnvVenv      EnvType = "venv"
	EnvConda     EnvType = "conda"
	EnvPoetry    EnvType = "poetry"
	EnvPipenv    EnvType = "pipenv"
	EnvSystemDeb EnvType = "system_deb"
	EnvSystemRpm EnvType = "system_rpm"
)

// PackageRecord represents a single installed Python package discovered on
// the device. Optional fields use omitempty to reduce JSON noise.
type PackageRecord struct {
	Name               string `json:"name"`
	Version            string `json:"version"`
	InstallPath        string `json:"install_path,omitempty"`
	EnvType            string `json:"env_type"`
	InterpreterVersion string `json:"interpreter_version,omitempty"`
	InstallerUser      string `json:"installer_user,omitempty"`
	InstallDate        string `json:"install_date,omitempty"`
	Environment        string `json:"environment"`
	LicenseRaw         string `json:"license_raw"`
	LicenseSPDX        string `json:"license_spdx"`
	LicenseTier        string `json:"license_tier"`
}

// ScanError records a non-fatal error encountered during scanning. The scanner
// never crashes on broken environments — it logs errors and continues.
type ScanError struct {
	Path      string    `json:"path"`
	EnvType   string    `json:"env_type,omitempty"`
	Error     string    `json:"error"`
	Timestamp time.Time `json:"timestamp"`
}

// ScanResult is the top-level output of a scan run. Both slices are always
// non-nil — an empty errors slice means a clean scan.
type ScanResult struct {
	DeviceID     string          `json:"device_id"`
	Hostname     string          `json:"hostname"`
	OS           string          `json:"os"`
	Arch         string          `json:"arch"`
	ScannedAt    time.Time       `json:"scanned_at"`
	Packages     []PackageRecord `json:"packages"`
	Errors       []ScanError     `json:"errors"`
	AgentVersion string          `json:"agent_version"`
}

// Config holds scanner configuration.
type Config struct {
	ScanRoot   string // Filesystem root to scan (default: / on Linux, C:\ on Windows)
	MaxDepth   int    // Max directory traversal depth (default: 8)
	MaxWorkers int    // Max concurrent environment scanners (default: 8)
}

