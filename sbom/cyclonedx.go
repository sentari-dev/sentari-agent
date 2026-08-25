// Package sbom generates CycloneDX and SPDX SBOM documents from scan results.
// SBOM output is opt-in: when the operator passes --sbom-out <path>, the agent
// writes a local CycloneDX SBOM file after the scan so air-gapped sites can
// extract it independently of the server.
package sbom

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/deptree"
)

// purlFor returns the Package-URL (purl) for a scanned package record,
// derived from its ecosystem (EnvType). Returns "" when no meaningful,
// standard purl can be produced — for ecosystems without a purl type
// (ai_agent, container, tcc, unknown) or when the version is empty (which
// would yield a dangling "pkg:npm/foo@"). Callers omit the purl when "".
//
// Ecosystem → purl type mapping:
//
//	pip / venv / conda / poetry / pipenv → pkg:pypi/
//	npm                                  → pkg:npm/
//	jvm                                  → pkg:maven/   (group:artifact split)
//	nuget                                → pkg:nuget/
//	go_binary                            → pkg:golang/  (lowercased module path)
//	system_deb                           → pkg:deb/
//	system_rpm                           → pkg:rpm/
//	everything else                      → "" (no purl)
func purlFor(pkg scanner.PackageRecord) string {
	if pkg.Version == "" {
		return ""
	}
	ver := url.PathEscape(pkg.Version)
	switch pkg.EnvType {
	case scanner.EnvPip, scanner.EnvVenv, scanner.EnvConda, scanner.EnvPoetry, scanner.EnvPipenv:
		return fmt.Sprintf("pkg:pypi/%s@%s", url.PathEscape(pkg.Name), ver)
	case "npm":
		// Scoped packages ("@scope/name") map to a purl namespace +
		// name: the scope's leading "@" is percent-encoded to "%40" and
		// the "/" between scope and name is a real path separator, NOT
		// "%2F". url.PathEscape would mangle the slash, so split on it
		// and escape each segment independently. Unscoped names ("name")
		// have no slash and pass through as a single escaped segment.
		if scope, name, ok := strings.Cut(pkg.Name, "/"); ok && strings.HasPrefix(scope, "@") {
			// url.PathEscape leaves "@" unescaped (it's an allowed
			// path sub-delimiter), so encode the leading "@" to "%40"
			// explicitly before escaping the rest of the scope segment.
			escScope := "%40" + url.PathEscape(strings.TrimPrefix(scope, "@"))
			return fmt.Sprintf("pkg:npm/%s/%s@%s",
				escScope, url.PathEscape(name), ver)
		}
		return fmt.Sprintf("pkg:npm/%s@%s", url.PathEscape(pkg.Name), ver)
	case "jvm":
		// JVM records carry the name as "groupID:artifactID"; the maven
		// purl spec is pkg:maven/<group>/<artifact>@<version>. If no colon
		// is present we fall back to the bare name under maven — the best
		// correct option without a separate group field.
		if group, artifact, ok := strings.Cut(pkg.Name, ":"); ok {
			return fmt.Sprintf("pkg:maven/%s/%s@%s",
				url.PathEscape(group), url.PathEscape(artifact), ver)
		}
		return fmt.Sprintf("pkg:maven/%s@%s", url.PathEscape(pkg.Name), ver)
	case "nuget":
		return fmt.Sprintf("pkg:nuget/%s@%s", url.PathEscape(pkg.Name), ver)
	case "go_binary":
		// purl-spec golang type: lowercase the whole module path (the
		// namespace + name), keeping "/" as real path separators. Escape
		// each segment individually so the slashes are not turned into
		// "%2F" (the scoped-npm segment-wise precedent above), then append
		// the escaped version.
		segments := strings.Split(strings.ToLower(pkg.Name), "/")
		for i, seg := range segments {
			segments[i] = url.PathEscape(seg)
		}
		return fmt.Sprintf("pkg:golang/%s@%s", strings.Join(segments, "/"), ver)
	case scanner.EnvSystemDeb:
		return fmt.Sprintf("pkg:deb/%s@%s", url.PathEscape(pkg.Name), ver)
	case scanner.EnvSystemRpm:
		return fmt.Sprintf("pkg:rpm/%s@%s", url.PathEscape(pkg.Name), ver)
	default:
		// ai_agent, container, tcc, runtime records, unknown — no
		// standard purl. Emit none rather than a wrong one.
		return ""
	}
}

// CycloneDXBOM represents a minimal CycloneDX 1.6 BOM in JSON format.
type CycloneDXBOM struct {
	BOMFormat    string                `json:"bomFormat"`
	SpecVersion  string                `json:"specVersion"`
	SerialNumber string                `json:"serialNumber"`
	Version      int                   `json:"version"`
	Metadata     CycloneDXMetadata     `json:"metadata"`
	Components   []CycloneDXComponent  `json:"components"`
	Dependencies []CycloneDXDependency `json:"dependencies,omitempty"`
}

// CycloneDXDependency is one node of the top-level dependency graph: a
// component ref and the sorted refs of the components it directly depends on.
type CycloneDXDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

// CycloneDXMetadata holds BOM metadata.
type CycloneDXMetadata struct {
	Timestamp string              `json:"timestamp"`
	Tools     []CycloneDXTool     `json:"tools"`
	Component *CycloneDXComponent `json:"component,omitempty"`
}

// CycloneDXTool identifies the tool that generated the BOM.
type CycloneDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// CycloneDXProperty is a name/value pair attached to a component.
type CycloneDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CycloneDXComponent represents a single component in the BOM.
type CycloneDXComponent struct {
	Type       string                   `json:"type"`
	BOMRef     string                   `json:"bom-ref,omitempty"`
	Name       string                   `json:"name"`
	Version    string                   `json:"version,omitempty"`
	Purl       string                   `json:"purl,omitempty"`
	Hashes     []CycloneDXHash          `json:"hashes,omitempty"`
	Supplier   *CycloneDXSupplier       `json:"supplier,omitempty"`
	Licenses   []CycloneDXLicenseChoice `json:"licenses,omitempty"`
	Properties []CycloneDXProperty      `json:"properties,omitempty"`
}

// CycloneDXSupplier is the CycloneDX supplier object; only the NTIA-required
// name is populated from locally readable metadata (PackageRecord.Supplier).
type CycloneDXSupplier struct {
	Name string `json:"name"`
}

// CycloneDXHash is one artifact hash; only SHA-256 of a single-file coordinate
// is emitted (PackageRecord.Sha256).
type CycloneDXHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// generateUUIDv4 returns a random RFC 4122 version-4 UUID string using
// crypto/rand — no external dependency needed.
func generateUUIDv4() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand.Read: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant RFC 4122
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32], nil
}

// GenerateCycloneDX creates a CycloneDX 1.6 JSON document from scan results.
func GenerateCycloneDX(result *scanner.ScanResult) ([]byte, error) {
	serialID, err := generateUUIDv4()
	if err != nil {
		return nil, fmt.Errorf("generate SBOM serial number: %w", err)
	}

	// One shared, deterministic component plan feeds both SBOM formats so
	// CycloneDX and SPDX can never disagree on ordering or bom-refs.
	plans, refByKey := planComponents(result)
	licenses := newLicenseIndex(result.LicenseEvidence)

	components := make([]CycloneDXComponent, 0, len(plans))
	for _, plan := range plans {
		pkg := plan.pkg
		comp := CycloneDXComponent{
			Type:    "library",
			BOMRef:  plan.ref,
			Name:    pkg.Name,
			Version: pkg.Version,
			Purl:    plan.purl,
		}
		if pkg.Sha256 != "" {
			comp.Hashes = []CycloneDXHash{{Alg: "SHA-256", Content: pkg.Sha256}}
		}
		if pkg.Supplier != "" {
			comp.Supplier = &CycloneDXSupplier{Name: pkg.Supplier}
		}
		comp.Licenses = resolveComponentLicenses(pkg, licenses).cyclonedx
		if pkg.InstallPath != "" {
			comp.Properties = []CycloneDXProperty{
				{Name: "sentari:install_path", Value: pkg.InstallPath},
			}
		}
		components = append(components, comp)
	}

	bom := CycloneDXBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: "urn:uuid:" + serialID,
		Version:      1,
		Metadata: CycloneDXMetadata{
			Timestamp: result.ScannedAt.Format(time.RFC3339),
			Tools: []CycloneDXTool{
				{
					Vendor:  "Sentari",
					Name:    "sentari-agent",
					Version: result.AgentVersion,
				},
			},
			Component: &CycloneDXComponent{
				Type:   "device",
				BOMRef: "device-" + result.Hostname,
				Name:   result.Hostname,
			},
		},
		Components:   components,
		Dependencies: buildCycloneDXDependencies(result.DepEdges, refByKey),
	}

	return json.MarshalIndent(bom, "", "  ")
}

// buildCycloneDXDependencies builds the top-level dependency graph from the
// scan's dependency edges. Each edge endpoint is resolved to a component
// bom-ref via its coordinate key (refByKey); an edge whose parent or child is
// not an installed component (uninstalled, version-mismatched, or from an
// ecosystem without a coordinate key) is silently dropped — an SBOM must never
// reference a node it does not contain. The result has one entry per parent
// with at least one surviving edge, entries sorted by ref, and each dependsOn
// list sorted and deduped. Returns nil when no edge resolves, so the caller's
// omitempty keeps edge-less documents free of an empty array.
func buildCycloneDXDependencies(edges []deptree.DepEdge, refByKey map[string]string) []CycloneDXDependency {
	depends := make(map[string]map[string]struct{})
	for _, e := range edges {
		parentRef, ok := refByKey[coordKey(e.Ecosystem, e.ParentName, e.ParentVersion)]
		if !ok {
			continue
		}
		childRef, ok := refByKey[coordKey(e.Ecosystem, e.ChildName, e.ChildVersion)]
		if !ok {
			continue
		}
		if depends[parentRef] == nil {
			depends[parentRef] = make(map[string]struct{})
		}
		depends[parentRef][childRef] = struct{}{}
	}
	if len(depends) == 0 {
		return nil
	}
	refs := make([]string, 0, len(depends))
	for ref := range depends {
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	out := make([]CycloneDXDependency, 0, len(refs))
	for _, ref := range refs {
		children := make([]string, 0, len(depends[ref]))
		for child := range depends[ref] {
			children = append(children, child)
		}
		sort.Strings(children)
		out = append(out, CycloneDXDependency{Ref: ref, DependsOn: children})
	}
	return out
}

// WriteCycloneDXToFile generates and writes the CycloneDX SBOM to disk.
func WriteCycloneDXToFile(result *scanner.ScanResult, outputPath string) error {
	data, err := GenerateCycloneDX(result)
	if err != nil {
		return fmt.Errorf("generate CycloneDX: %w", err)
	}
	// Use 0600 — SBOM files may contain sensitive dependency information.
	return os.WriteFile(outputPath, data, 0600)
}
