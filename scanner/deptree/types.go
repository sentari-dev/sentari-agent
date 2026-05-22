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
//
// The v3 schema requires introduced_by_path to have minItems=2;
// emitters that look the chain up in a precomputed map MUST go through
// SafePath so an orphan (parent not BFS-reached from root) cannot
// produce a nil slice — Go's encoding/json would marshal that as
// `null`, which the server rejects with 422 and which violates
// minItems=2 anyway.  Discovered on 2026-05-20: pypi orphans were
// shipping ~9% of dep_edges as `null` and the server's Pydantic model
// silently dropped them with HTTP 422.
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

// SafePath returns an introduced_by_path that satisfies the v3 schema's
// minItems=2 constraint.  When the precomputed path is nil or shorter
// than 2 entries (e.g. a BFS-unreached orphan in the parsed dep map),
// it falls back to the minimal valid [parent, child] chain.  This is
// the localized defense against the "null introduced_by_path" bug; the
// server also coerces None→[] on ingest as belt-and-braces.
func SafePath(path []string, parent, child string) []string {
	if len(path) >= 2 {
		return path
	}
	return []string{parent, child}
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
