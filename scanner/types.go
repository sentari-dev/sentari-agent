// Package scanner detects all Python environments on a device and extracts
// package metadata. It is the core of the sentari-agent and has zero network
// dependencies — it only reads the local filesystem.
package scanner

import (
	"fmt"
	"os"
	"time"
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

// readFileBounded reads a file into memory only if its size is within maxSize.
// This prevents OOM from maliciously crafted or corrupted metadata files.
func readFileBounded(path string, maxSize int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() > maxSize {
		return nil, fmt.Errorf("file too large (%d bytes, limit %d): %s", info.Size(), maxSize, path)
	}
	return os.ReadFile(path)
}
