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
	// Container-origin fields — populated only when the scan was
	// performed inside a container's merged rootfs (Sprint-17
	// container-image scanner, opt-in via Config.ScanContainers).
	// Empty on all host-filesystem records.  Server-side filters
	// "show me CVEs inside containers" key on ContainerImageID != "".
	ContainerImageID   string   `json:"container_image_id,omitempty"`
	ContainerImageTags []string `json:"container_image_tags,omitempty"`
	ContainerID        string   `json:"container_id,omitempty"`
	ContainerName      string   `json:"container_name,omitempty"`
	ContainerRuntime   string   `json:"container_runtime,omitempty"`
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
	// ContainerTargets lists every container/image the container
	// discoverer enumerated this scan cycle.  Informational: agents
	// may have ScanContainers disabled yet still surface "which
	// containers live on this host" in the fleet dashboard.
	// Populated only when ScanContainers is true OR when the caller
	// explicitly invokes the discoverer; otherwise nil.
	ContainerTargets []ContainerTargetSummary `json:"container_targets,omitempty"`

	// Tags is the operator-supplied per-host metadata from
	// ``[agent] tags = ...`` in agent.conf.  Pointer-to-slice
	// because we need three distinguishable wire states:
	//
	//   nil           → field omitted on the wire entirely
	//                   (older agent / config has no [agent] section)
	//                   → server leaves device.tags_agent untouched
	//   &[]string{}   → field serialises as ``"tags": []``
	//                   (operator wrote ``tags =`` with no values)
	//                   → server clears device.tags_agent
	//   &[]string{…}  → field serialises as ``"tags": [...]``
	//                   → server applies the canonical list
	//
	// Plain ``[]string`` + ``omitempty`` would conflate the first
	// two cases (Go encoding/json treats nil and empty slices both
	// as "empty" → both omitted from JSON), making "explicit clear"
	// indistinguishable from "no tags configured".
	Tags *[]string `json:"tags,omitempty"`

	// Runtime is the auto-detected host classification — one of
	// ``bare_metal``, ``container``, ``k8s``, ``unknown``.  Sent
	// on every scan; the server runs the propose-then-approve
	// workflow (sentari PR #79).  Empty string is back-compat for
	// older agents — server treats as "field absent" and leaves
	// ``device.runtime`` untouched.
	Runtime string `json:"runtime,omitempty"`
}

// ContainerTargetSummary is the informational shape of a discovered
// container or image, carried on ScanResult so the server can
// populate a "containers on this host" dashboard without having to
// wait for the full merged-view scan.  The scan-result schema
// expands via optional fields only; omitempty keeps the JSON quiet
// on hosts with no containers.
type ContainerTargetSummary struct {
	Runtime       string   `json:"runtime"`
	ImageID       string   `json:"image_id"`
	ImageTags     []string `json:"image_tags,omitempty"`
	ContainerID   string   `json:"container_id,omitempty"`
	ContainerName string   `json:"container_name,omitempty"`
	// LayerCount is informational: a high count can indicate a
	// bloated uber-image and drives the "slow scan" explanation in
	// support tickets.
	LayerCount int `json:"layer_count"`
}

// Config holds scanner configuration.
type Config struct {
	ScanRoot   string // Filesystem root to scan (default: / on Linux, C:\ on Windows)
	MaxDepth   int    // Max directory traversal depth (default: 8)
	MaxWorkers int    // Max concurrent environment scanners (default: 8)
	// ScanContainers enables the Sprint-17 container-image scanner.
	// When true, Runner.Run (via the orchestration wrapper in
	// scanner/containers) discovers every image/container on the
	// host from supported runtimes (Docker, Podman, CRI-O), builds
	// a virtual merged rootfs per target, and runs the existing
	// plugin registry against each.  Defaults to false: fleet-wide
	// rollout is opt-in until the performance shape is measured.
	// Env override: SENTARI_SCAN_CONTAINERS=true.
	ScanContainers bool
	// MaxContainersPerCycle caps the number of containers scanned
	// per cycle to protect against CI nodes with hundreds of
	// ephemeral containers.  0 = use default (100).
	MaxContainersPerCycle int
	// PerContainerTimeout bounds the time spent scanning one
	// container.  Exceeded => ScanError, continue with next.
	// 0 = use default (60s).
	PerContainerTimeout time.Duration
}

