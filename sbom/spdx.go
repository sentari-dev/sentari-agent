package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/deptree"
)

// SPDXDocument is a minimal SPDX 2.3 document in JSON format.
// Reference: https://spdx.github.io/spdx-spec/v2.3/
type SPDXDocument struct {
	SPDXID            string             `json:"SPDXID"`
	SPDXVersion       string             `json:"spdxVersion"`
	CreationInfo      SPDXCreation       `json:"creationInfo"`
	Name              string             `json:"name"`
	DataLicense       string             `json:"dataLicense"`
	DocumentNamespace string             `json:"documentNamespace"`
	Packages          []SPDXPackage      `json:"packages"`
	Relationships     []SPDXRelationship `json:"relationships"`
}

// SPDXRelationship records a directed relationship between two SPDX elements.
// SPDX 2.3 requires at least a SPDXRef-DOCUMENT DESCRIBES <package> edge so
// consumers know which elements the document describes.
type SPDXRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// SPDXCreation holds document creation metadata.
type SPDXCreation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

// SPDXExternalRef is an external reference attached to an SPDX package
// (used here to carry the purl identifier).
type SPDXExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// SPDXPackage represents a single package element in the SPDX document.
type SPDXPackage struct {
	SPDXID           string            `json:"SPDXID"`
	Name             string            `json:"name"`
	VersionInfo      string            `json:"versionInfo"`
	DownloadLocation string            `json:"downloadLocation"`
	FilesAnalyzed    bool              `json:"filesAnalyzed"`
	Checksums        []SPDXChecksum    `json:"checksums,omitempty"`
	Supplier         string            `json:"supplier,omitempty"`
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	CopyrightText    string            `json:"copyrightText"`
	ExternalRefs     []SPDXExternalRef `json:"externalRefs,omitempty"`
}

// SPDXChecksum is one artifact checksum; only SHA256 of a single-file
// coordinate is emitted (PackageRecord.Sha256).
type SPDXChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

// spdxSupplier formats a supplier name into the SPDX 2.3 grammar
// ("Organization: <name>"); "" when there is no supplier, so the field is
// omitted rather than emitting a bare or malformed value.
func spdxSupplier(name string) string {
	if name == "" {
		return ""
	}
	return "Organization: " + name
}

// spdxChecksums returns the single SHA256 checksum entry when a hash is present,
// else nil (the field is omitted — no fake placeholder for an unhashed
// multi-file coordinate).
func spdxChecksums(sha256 string) []SPDXChecksum {
	if sha256 == "" {
		return nil
	}
	return []SPDXChecksum{{Algorithm: "SHA256", ChecksumValue: sha256}}
}

// GenerateSPDX creates an SPDX 2.3 JSON document from scan results.
func GenerateSPDX(result *scanner.ScanResult) ([]byte, error) {
	serialID, err := generateUUIDv4()
	if err != nil {
		return nil, fmt.Errorf("generate SBOM serial number: %w", err)
	}
	namespace := fmt.Sprintf("https://sentari.io/sbom/%s", serialID)

	// The same shared plan the CycloneDX generator uses, so SPDX package ids
	// and CycloneDX bom-refs are assigned in one identical order.
	plans, _ := planComponents(result)
	licenses := newLicenseIndex(result.LicenseEvidence)

	packages := make([]SPDXPackage, 0, len(plans))
	relationships := make([]SPDXRelationship, 0, len(plans))
	// idByKey maps a package coordinate to the SPDX id of its first (sorted
	// lowest) instance — the canonical graph node dependency edges attach to.
	idByKey := make(map[string]string, len(plans))
	for i, plan := range plans {
		pkg := plan.pkg
		spdxID := fmt.Sprintf("SPDXRef-Package-%d", i)
		lic := resolveComponentLicenses(pkg, licenses)
		p := SPDXPackage{
			SPDXID:           spdxID,
			Name:             pkg.Name,
			VersionInfo:      pkg.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			Checksums:        spdxChecksums(pkg.Sha256),
			Supplier:         spdxSupplier(pkg.Supplier),
			LicenseConcluded: lic.concluded,
			LicenseDeclared:  lic.declared,
			CopyrightText:    lic.copyright,
		}
		// Attach a purl external ref only when the ecosystem yields a
		// correct, standard purl (see sbom.purlFor). Omitting it is
		// preferable to emitting a wrong pkg:pypi/ locator.
		if plan.purl != "" {
			p.ExternalRefs = []SPDXExternalRef{
				{
					ReferenceCategory: "PACKAGE-MANAGER",
					ReferenceType:     "purl",
					ReferenceLocator:  plan.purl,
				},
			}
		}
		packages = append(packages, p)
		relationships = append(relationships, SPDXRelationship{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: spdxID,
		})
		if key := coordKey(envTypeEcosystem(pkg.EnvType), pkg.Name, pkg.Version); key != "" {
			if _, ok := idByKey[key]; !ok {
				idByKey[key] = spdxID
			}
		}
	}
	// DEPENDS_ON relationships follow the full DESCRIBES block (SPDX 2.3).
	relationships = append(relationships, buildSPDXDependsOn(result.DepEdges, idByKey)...)

	doc := SPDXDocument{
		SPDXID:      "SPDXRef-DOCUMENT",
		SPDXVersion: "SPDX-2.3",
		CreationInfo: SPDXCreation{
			Created: result.ScannedAt.UTC().Format("2006-01-02T15:04:05Z"),
			Creators: []string{
				fmt.Sprintf("Tool: sentari-agent-%s", result.AgentVersion),
				fmt.Sprintf("Device: %s", result.Hostname),
			},
		},
		Name:              fmt.Sprintf("sentari-sbom-%s", result.Hostname),
		DataLicense:       "CC0-1.0",
		DocumentNamespace: namespace,
		Packages:          packages,
		Relationships:     relationships,
	}

	return json.MarshalIndent(doc, "", "  ")
}

// buildSPDXDependsOn builds the DEPENDS_ON relationships from the scan's
// dependency edges. Each endpoint resolves to a package SPDX id via its
// coordinate key (idByKey); an edge with an unresolved endpoint (uninstalled,
// version-mismatched, or from an ecosystem without a coordinate key) is dropped
// so no relationship references a package absent from the document. Pairs are
// deduped and sorted by (parent id, child id). Returns nil when nothing
// resolves.
func buildSPDXDependsOn(edges []deptree.DepEdge, idByKey map[string]string) []SPDXRelationship {
	type pair struct{ parent, child string }
	seen := make(map[pair]struct{})
	for _, e := range edges {
		parentID, ok := idByKey[coordKey(e.Ecosystem, e.ParentName, e.ParentVersion)]
		if !ok {
			continue
		}
		childID, ok := idByKey[coordKey(e.Ecosystem, e.ChildName, e.ChildVersion)]
		if !ok {
			continue
		}
		seen[pair{parent: parentID, child: childID}] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	pairs := make([]pair, 0, len(seen))
	for p := range seen {
		pairs = append(pairs, p)
	}
	sort.Slice(pairs, func(a, b int) bool {
		if pairs[a].parent != pairs[b].parent {
			return pairs[a].parent < pairs[b].parent
		}
		return pairs[a].child < pairs[b].child
	})
	out := make([]SPDXRelationship, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, SPDXRelationship{
			SPDXElementID:      p.parent,
			RelationshipType:   "DEPENDS_ON",
			RelatedSPDXElement: p.child,
		})
	}
	return out
}

// WriteSPDXToFile generates and writes the SPDX SBOM to disk.
func WriteSPDXToFile(result *scanner.ScanResult, outputPath string) error {
	data, err := GenerateSPDX(result)
	if err != nil {
		return fmt.Errorf("generate SPDX: %w", err)
	}
	// Use 0600 — SBOM files may contain sensitive dependency information.
	return os.WriteFile(outputPath, data, 0600)
}
