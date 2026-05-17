package licenses

import (
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
)

// ExtractNuGet walks the NuGet packages cache for *.nuspec files. The
// modern nuspec uses <license type="expression">SPDX</license> (conf
// 0.9); older nuspec used <licenseUrl> as a free-text URL (conf 0.5).
func ExtractNuGet(cacheRoot string) ([]deptree.LicenseEvidence, error) {
	var out []deptree.LicenseEvidence
	walkErr := filepath.WalkDir(cacheRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".nuspec") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		var ns nugetNuspec
		if err := xml.Unmarshal(raw, &ns); err != nil {
			return nil
		}
		md := ns.Metadata
		if md.ID == "" {
			return nil
		}
		// Prefer <license> SPDX element.
		if md.License.Value != "" && strings.EqualFold(md.License.Type, "expression") {
			out = append(out, deptree.LicenseEvidence{
				PackageName:    md.ID,
				PackageVersion: md.Version,
				Ecosystem:      "nuget",
				SpdxID:         md.License.Value,
				Source:         "nuspec",
				Confidence:     0.9,
				RawText:        md.License.Value,
			})
		} else if md.LicenseURL != "" {
			out = append(out, deptree.LicenseEvidence{
				PackageName:    md.ID,
				PackageVersion: md.Version,
				Ecosystem:      "nuget",
				SpdxID:         "",
				Source:         "nuspec",
				Confidence:     0.5,
				RawText:        md.LicenseURL,
			})
		}
		return nil
	})
	if walkErr != nil {
		return out, fmt.Errorf("walk %s: %w", cacheRoot, walkErr)
	}
	return out, nil
}

type nugetNuspec struct {
	Metadata struct {
		ID         string         `xml:"id"`
		Version    string         `xml:"version"`
		License    nugetLicenseEl `xml:"license"`
		LicenseURL string         `xml:"licenseUrl"`
	} `xml:"metadata"`
}

type nugetLicenseEl struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}
