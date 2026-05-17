package licenses

import (
	"encoding/xml"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// maxPOMBytes caps a single .pom read in ~/.m2/repository.  POMs are
// declarative XML; 1 MiB is well above realistic sizes.
const maxPOMBytes = 1 << 20 // 1 MiB

// ExtractMaven walks ~/.m2/repository for *.pom files and reads each
// pom's <licenses><license><name> entries. Confidence 0.9 — POM
// licenses are author-declared and aren't validated SPDX, but they're
// the canonical source for Maven projects.
func ExtractMaven(m2Dir string) ([]deptree.LicenseEvidence, error) {
	var out []deptree.LicenseEvidence
	walkErr := filepath.WalkDir(m2Dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".pom") {
			return nil
		}
		raw, err := safeio.ReadFile(path, maxPOMBytes)
		if err != nil {
			return nil
		}
		var pom mavenPomDoc
		if err := xml.Unmarshal(raw, &pom); err != nil {
			return nil
		}
		if pom.ArtifactID == "" {
			return nil
		}
		name := pom.GroupID + ":" + pom.ArtifactID
		for _, lic := range pom.Licenses.Licenses {
			if lic.Name == "" {
				continue
			}
			out = append(out, deptree.LicenseEvidence{
				PackageName:    name,
				PackageVersion: pom.Version,
				Ecosystem:      "maven",
				SpdxID:         "",
				Source:         "pom",
				Confidence:     0.9,
				RawText:        lic.Name,
			})
		}
		return nil
	})
	if walkErr != nil {
		return out, fmt.Errorf("walk %s: %w", m2Dir, walkErr)
	}
	return out, nil
}

type mavenPomDoc struct {
	XMLName    xml.Name `xml:"project"`
	GroupID    string   `xml:"groupId"`
	ArtifactID string   `xml:"artifactId"`
	Version    string   `xml:"version"`
	Licenses   struct {
		Licenses []mavenLicense `xml:"license"`
	} `xml:"licenses"`
}

type mavenLicense struct {
	Name string `xml:"name"`
	URL  string `xml:"url"`
}
