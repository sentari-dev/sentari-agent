package sbom

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/sentari-dev/sentari-agent/scanner"
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
	LicenseConcluded string            `json:"licenseConcluded"`
	LicenseDeclared  string            `json:"licenseDeclared"`
	ExternalRefs     []SPDXExternalRef `json:"externalRefs,omitempty"`
}

// GenerateSPDX creates an SPDX 2.3 JSON document from scan results.
func GenerateSPDX(result *scanner.ScanResult) ([]byte, error) {
	serialID, err := generateUUIDv4()
	if err != nil {
		return nil, fmt.Errorf("generate SBOM serial number: %w", err)
	}
	namespace := fmt.Sprintf("https://sentari.io/sbom/%s", serialID)

	packages := make([]SPDXPackage, 0, len(result.Packages))
	relationships := make([]SPDXRelationship, 0, len(result.Packages))
	for i, pkg := range result.Packages {
		spdxID := fmt.Sprintf("SPDXRef-Package-%d", i)
		p := SPDXPackage{
			SPDXID:           spdxID,
			Name:             pkg.Name,
			VersionInfo:      pkg.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			LicenseConcluded: "NOASSERTION",
			LicenseDeclared:  "NOASSERTION",
		}
		// Attach a purl external ref only when the ecosystem yields a
		// correct, standard purl (see sbom.purlFor). Omitting it is
		// preferable to emitting a wrong pkg:pypi/ locator.
		if purl := purlFor(pkg); purl != "" {
			p.ExternalRefs = []SPDXExternalRef{
				{
					ReferenceCategory: "PACKAGE-MANAGER",
					ReferenceType:     "purl",
					ReferenceLocator:  purl,
				},
			}
		}
		packages = append(packages, p)
		relationships = append(relationships, SPDXRelationship{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: spdxID,
		})
	}

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

// WriteSPDXToFile generates and writes the SPDX SBOM to disk.
func WriteSPDXToFile(result *scanner.ScanResult, outputPath string) error {
	data, err := GenerateSPDX(result)
	if err != nil {
		return fmt.Errorf("generate SPDX: %w", err)
	}
	// Use 0600 — SBOM files may contain sensitive dependency information.
	return os.WriteFile(outputPath, data, 0600)
}
