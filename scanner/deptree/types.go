// Package deptree carries the v3 agent scan payload types: dep-graph
// edges, lockfile metadata, supply-chain signals, and license evidence.
//
// The struct shapes mirror docs/contracts/agent-scan-payload-v3.{md,json}
// — the source-of-truth schema shared with the sentari server repo.
package deptree

import "time"

// DepEdge is one direct or transitive dependency edge from a project's
// dep graph. introduced_by_path is the full root-to-leaf chain
// inclusive of both endpoints (see contract doc for examples).
type DepEdge struct {
	ParentName       string   `json:"parent_name"`
	ParentVersion    string   `json:"parent_version"`
	ChildName        string   `json:"child_name"`
	ChildVersion     string   `json:"child_version"`
	Ecosystem        string   `json:"ecosystem"`
	Type             string   `json:"type"`
	Scope            string   `json:"scope"`
	Depth            int      `json:"depth"`
	IntroducedByPath []string `json:"introduced_by_path"`
	Resolved         bool     `json:"resolved"`
}

// LockfileMeta is one discovered lockfile's metadata. The agent does
// NOT upload the lockfile content — only this header.
type LockfileMeta struct {
	Path                  string    `json:"path"`
	Format                string    `json:"format"`
	Ecosystem             string    `json:"ecosystem"`
	SHA256                string    `json:"sha256"`
	LastModified          time.Time `json:"last_modified"`
	DeclaredPackagesCount int       `json:"declared_packages_count"`
	DriftStatus           string    `json:"drift_status"`
}

// SupplyChainSignal is one agent-detected supply-chain risk for a
// specific package. Server-side enrichment also writes to this table
// using a different set of signal types (deprecated, maintainer_changed,
// typosquat_suspect, npm_malware_advisory) — agents MUST NOT emit those.
type SupplyChainSignal struct {
	PackageName    string                 `json:"package_name"`
	PackageVersion string                 `json:"package_version"`
	Ecosystem      string                 `json:"ecosystem"`
	SignalType     string                 `json:"signal_type"`
	Severity       string                 `json:"severity"`
	Source         string                 `json:"source"`
	Raw            map[string]interface{} `json:"raw,omitempty"`
}

// LicenseEvidence is one license discovery from an agent-side
// per-ecosystem extractor. The server's package_licenses table
// ingests these rows directly.
type LicenseEvidence struct {
	PackageName    string  `json:"package_name"`
	PackageVersion string  `json:"package_version"`
	Ecosystem      string  `json:"ecosystem"`
	SpdxID         string  `json:"spdx_id,omitempty"`
	Source         string  `json:"source"`
	Confidence     float64 `json:"confidence"`
	RawText        string  `json:"raw_text,omitempty"`
}
