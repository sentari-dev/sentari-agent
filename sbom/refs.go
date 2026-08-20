package sbom

import (
	"fmt"
	"sort"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// envTypeEcosystem maps a scanner EnvType to the package-URL ecosystem token
// used as the coordinate namespace for dependency-graph edge matching. It
// mirrors the purl type selection in purlFor for the ecosystems that carry a
// dependency graph:
//
//	pip / venv / conda / poetry / pipenv → pypi
//	npm                                  → npm
//	jvm                                  → maven
//	nuget                                → nuget
//
// Every other EnvType (system_deb, system_rpm, go_binary, ai_agent, …) returns
// "" — those records never appear as dependency-edge endpoints, so they get no
// coordinate key.
func envTypeEcosystem(envType string) string {
	switch envType {
	case scanner.EnvPip, scanner.EnvVenv, scanner.EnvConda, scanner.EnvPoetry, scanner.EnvPipenv:
		return "pypi"
	case "npm":
		return "npm"
	case "jvm":
		return "maven"
	case "nuget":
		return "nuget"
	default:
		return ""
	}
}

// foldName normalizes a package name for coordinate comparison. Every ecosystem
// folds to lowercase; PyPI additionally applies PEP-503 normalization, mapping
// "_" and "." to "-" so that a dependency edge naming "Typing_Extensions" or
// "zope.interface" matches the installed distribution "typing-extensions" /
// "zope-interface".
func foldName(ecosystem, name string) string {
	lower := make([]byte, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if ecosystem == "pypi" && (c == '_' || c == '.') {
			c = '-'
		}
		lower[i] = c
	}
	return string(lower)
}

// coordKey builds the coordinate key that ties a scanned package to a
// dependency-edge endpoint: "<ecosystem>|<foldName(name)>|<version>". An empty
// ecosystem yields "" (no key) — the caller then skips the record, as
// non-graph ecosystems can never be referenced by an edge.
func coordKey(ecosystem, name, version string) string {
	if ecosystem == "" {
		return ""
	}
	return ecosystem + "|" + foldName(ecosystem, name) + "|" + version
}

// componentPlan is one package's resolved placement in the SBOM: the record
// itself, its purl ("" when none applies), and the unique bom-ref assigned in
// sorted order.
type componentPlan struct {
	pkg  scanner.PackageRecord
	purl string
	ref  string
}

// planComponents computes the single, deterministic component ordering shared
// by both the CycloneDX and SPDX generators, so the two formats can never drift
// on which component is which. For each package it derives:
//
//   - purl (via purlFor) — "" when the ecosystem has no standard purl;
//   - baseRef — the purl when present, else the coordinate form
//     "<ecosystem>:<name>@<version>" (index-free, so output survives input
//     reordering).
//
// Packages are sorted by (baseRef, InstallPath, original index) — a total
// order: identical coordinates are ordered by install path (the same package in
// /opt/venv-a sorts before /opt/venv-b), with the original index as the final
// tie-break. Unique bom-refs are then assigned in that sorted order, with a
// "#<n>" suffix disambiguating collisions (CycloneDX requires every bom-ref to
// be unique within the BOM).
//
// The returned map keys each package coordinate (coordKey of its mapped
// ecosystem) to the bom-ref of its first (sorted-lowest) instance: a coordinate
// installed in N environments yields N components but ONE canonical graph node,
// the unsuffixed ref, which dependency edges attach to.
func planComponents(result *scanner.ScanResult) ([]componentPlan, map[string]string) {
	type entry struct {
		pkg     scanner.PackageRecord
		purl    string
		baseRef string
		origIdx int
	}
	entries := make([]entry, 0, len(result.Packages))
	for i, pkg := range result.Packages {
		purl := purlFor(pkg)
		baseRef := purl
		if baseRef == "" {
			eco := envTypeEcosystem(pkg.EnvType)
			if eco == "" {
				eco = pkg.EnvType
			}
			if eco == "" {
				eco = "unknown"
			}
			baseRef = fmt.Sprintf("%s:%s@%s", eco, pkg.Name, pkg.Version)
		}
		entries = append(entries, entry{pkg: pkg, purl: purl, baseRef: baseRef, origIdx: i})
	}

	sort.SliceStable(entries, func(a, b int) bool {
		if entries[a].baseRef != entries[b].baseRef {
			return entries[a].baseRef < entries[b].baseRef
		}
		if entries[a].pkg.InstallPath != entries[b].pkg.InstallPath {
			return entries[a].pkg.InstallPath < entries[b].pkg.InstallPath
		}
		return entries[a].origIdx < entries[b].origIdx
	})

	plans := make([]componentPlan, 0, len(entries))
	refByKey := make(map[string]string, len(entries))

	// CycloneDX requires every bom-ref to be unique within the BOM. The same
	// package (identical purl) can legitimately appear in multiple environments
	// on one device, which would otherwise collide. Track the base bom-refs
	// we've emitted and disambiguate collisions with a "#<n>" suffix. The purl
	// field itself is left untouched so the component's package identity (and
	// the scoped-npm purl encoding) stays correct.
	usedRefs := make(map[string]int, len(entries))
	for _, e := range entries {
		bomRef := e.baseRef
		// Ensure uniqueness: on the first sighting keep the base ref; on each
		// subsequent collision append "#1", "#2", ...
		if n := usedRefs[bomRef]; n > 0 {
			unique := fmt.Sprintf("%s#%d", bomRef, n)
			// Guard against an (improbable) crafted collision between a
			// suffixed ref and an existing base ref.
			for usedRefs[unique] > 0 {
				n++
				unique = fmt.Sprintf("%s#%d", bomRef, n)
			}
			usedRefs[bomRef] = n + 1
			usedRefs[unique] = 1
			bomRef = unique
		} else {
			usedRefs[bomRef] = 1
		}
		plans = append(plans, componentPlan{pkg: e.pkg, purl: e.purl, ref: bomRef})
		if key := coordKey(envTypeEcosystem(e.pkg.EnvType), e.pkg.Name, e.pkg.Version); key != "" {
			if _, ok := refByKey[key]; !ok {
				refByKey[key] = bomRef
			}
		}
	}
	return plans, refByKey
}
