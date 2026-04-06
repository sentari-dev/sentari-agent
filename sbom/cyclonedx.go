// Package sbom generates CycloneDX and SPDX SBOM documents from scan results.
// The agent writes a local SBOM file after every scan so air-gapped sites
// can extract it independently of the server.
package sbom

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// CycloneDXBOM represents a minimal CycloneDX 1.6 BOM in JSON format.
type CycloneDXBOM struct {
	BOMFormat    string               `json:"bomFormat"`
	SpecVersion  string               `json:"specVersion"`
	SerialNumber string               `json:"serialNumber"`
	Version      int                  `json:"version"`
	Metadata     CycloneDXMetadata    `json:"metadata"`
	Components   []CycloneDXComponent `json:"components"`
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
	Type       string              `json:"type"`
	Name       string              `json:"name"`
	Version    string              `json:"version,omitempty"`
	Purl       string              `json:"purl,omitempty"`
	Properties []CycloneDXProperty `json:"properties,omitempty"`
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

	components := make([]CycloneDXComponent, 0, len(result.Packages))

	for _, pkg := range result.Packages {
		comp := CycloneDXComponent{
			Type:    "library",
			Name:    pkg.Name,
			Version: pkg.Version,
			Purl:    fmt.Sprintf("pkg:pypi/%s@%s", url.PathEscape(pkg.Name), url.PathEscape(pkg.Version)),
		}
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
				Type: "device",
				Name: result.Hostname,
			},
		},
		Components: components,
	}

	return json.MarshalIndent(bom, "", "  ")
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
