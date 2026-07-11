//go:build enterprise

package main

import (
	"fmt"
	"strings"

	"github.com/sentari-dev/sentari-agent/sbom"
	"github.com/sentari-dev/sentari-agent/scanner"
)

// normalizeSBOMFormat lower-cases and validates the --sbom-format value.
// Only cyclonedx and spdx are supported; an empty value defaults to cyclonedx
// (back-compat with the era when --sbom-out always emitted CycloneDX).
func normalizeSBOMFormat(format string) (string, error) {
	switch f := strings.ToLower(strings.TrimSpace(format)); f {
	case "", "cyclonedx":
		return "cyclonedx", nil
	case "spdx":
		return "spdx", nil
	default:
		return "", fmt.Errorf("invalid --sbom-format %q (want cyclonedx or spdx)", format)
	}
}

// writeSBOMFile writes the scan result as an SBOM in the requested (already
// validated) format.  Kept as a thin dispatch so runUpload's SBOM branch stays
// format-agnostic.
func writeSBOMFile(result *scanner.ScanResult, path, format string) error {
	switch format {
	case "spdx":
		return sbom.WriteSPDXToFile(result, path)
	default:
		return sbom.WriteCycloneDXToFile(result, path)
	}
}
