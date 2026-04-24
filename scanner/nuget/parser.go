package nuget

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// maxNuspecBytes caps any single nuspec read.  Real manifests are
// a few KiB; 512 KiB is generous headroom without letting a
// hostile or corrupt file OOM us.
const maxNuspecBytes = 512 * 1024

// nuspecManifest is the subset of .nuspec XML we consume.  The
// real schema carries many more fields (dependencies, icon,
// readme, repository); identity fields are all we need.
//
// NuGet's license handling has two shapes in the wild:
//   - Modern: <license type="expression|file">EXPR-OR-PATH</license>
//   - Legacy: <licenseUrl>https://...</licenseUrl>
// We surface both into LicenseRaw via extractLicense().
type nuspecManifest struct {
	XMLName  xml.Name `xml:"package"`
	Metadata struct {
		ID         string `xml:"id"`
		Version    string `xml:"version"`
		Authors    string `xml:"authors"`
		License    struct {
			Type  string `xml:"type,attr"`
			Value string `xml:",chardata"`
		} `xml:"license"`
		LicenseURL string `xml:"licenseUrl"`
	} `xml:"metadata"`
}

// scanGlobalPackages walks the NuGet global-packages folder and
// emits one PackageRecord per ``<id>/<version>/<id>.nuspec`` we
// find.  Layout:
//
//     <root>/
//       newtonsoft.json/
//         13.0.3/
//           newtonsoft.json.nuspec
//           newtonsoft.json.13.0.3.nupkg
//
// NuGet stores IDs lowercased on disk but the manifest carries
// the canonical casing (``Newtonsoft.Json``).  We use the
// manifest's casing for the record name so CVE correlation
// against OSV-nuget advisories matches.
func scanGlobalPackages(root string) ([]scanner.PackageRecord, []scanner.ScanError) {
	var (
		records []scanner.PackageRecord
		errs    []scanner.ScanError
	)

	idEntries, err := os.ReadDir(root)
	if err != nil {
		return nil, []scanner.ScanError{{
			Path:      root,
			EnvType:   EnvNuGet,
			Error:     fmt.Sprintf("readdir nuget packages: %v", err),
			Timestamp: time.Now().UTC(),
		}}
	}

	for _, idEntry := range idEntries {
		// Skip symlinked directory entries — same reasoning as the
		// npm plugin.  NuGet doesn't use symlinks in the global
		// packages folder on any supported platform, but a
		// hostile layer could plant one.
		if idEntry.Type()&os.ModeSymlink != 0 {
			continue
		}
		if !idEntry.IsDir() {
			continue
		}
		if strings.HasPrefix(idEntry.Name(), ".") {
			continue
		}

		idDir := filepath.Join(root, idEntry.Name())
		versionEntries, err := os.ReadDir(idDir)
		if err != nil {
			errs = append(errs, scanner.ScanError{
				Path:      idDir,
				EnvType:   EnvNuGet,
				Error:     fmt.Sprintf("readdir %s: %v", idEntry.Name(), err),
				Timestamp: time.Now().UTC(),
			})
			continue
		}
		for _, verEntry := range versionEntries {
			if verEntry.Type()&os.ModeSymlink != 0 {
				continue
			}
			if !verEntry.IsDir() {
				continue
			}
			if strings.HasPrefix(verEntry.Name(), ".") {
				continue
			}
			pkgDir := filepath.Join(idDir, verEntry.Name())
			rec, err := parsePackageVersionDir(root, idEntry.Name(), pkgDir)
			if err != nil {
				errs = append(errs, scanner.ScanError{
					Path:      pkgDir,
					EnvType:   EnvNuGet,
					Error:     err.Error(),
					Timestamp: time.Now().UTC(),
				})
				continue
			}
			if rec != nil {
				records = append(records, *rec)
			}
		}
	}
	return records, errs
}

// parsePackageVersionDir reads ``<pkgDir>/<idDirName>.nuspec``
// and returns a PackageRecord.  NuGet names the nuspec after the
// lowercase package ID (``newtonsoft.json.nuspec``) not the
// manifest's canonical casing.  Returns (nil, nil) when the
// directory isn't a valid package (no nuspec, missing
// id/version); the common case for stray dirs.
//
// ``envRoot`` is the global-packages folder — stamped on
// ``Environment`` so every record from the same install groups
// together on the server-side dashboard regardless of ID/version.
func parsePackageVersionDir(envRoot, idDirName, pkgDir string) (*scanner.PackageRecord, error) {
	nuspecPath := filepath.Join(pkgDir, idDirName+".nuspec")
	data, mtime, err := safeio.ReadFileWithMTime(nuspecPath, maxNuspecBytes)
	if err != nil {
		if os.IsNotExist(err) {
			// Not a valid package dir — silent skip.
			return nil, nil //nolint:nilnil // idiomatic here
		}
		return nil, fmt.Errorf("read nuspec: %w", err)
	}
	var m nuspecManifest
	if err := xml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse nuspec: %w", err)
	}
	if m.Metadata.ID == "" || m.Metadata.Version == "" {
		return nil, nil //nolint:nilnil
	}
	return &scanner.PackageRecord{
		Name:          m.Metadata.ID,
		Version:       m.Metadata.Version,
		InstallPath:   pkgDir,
		EnvType:       EnvNuGet,
		Environment:   envRoot,
		LicenseRaw:    extractLicense(m),
		InstallerUser: strings.TrimSpace(m.Metadata.Authors),
		InstallDate:   mtime.Format(time.RFC3339),
	}, nil
}

// extractLicense reduces nuspec's two license shapes to a single
// string for downstream SPDX normalisation.  Returns "" when
// nothing parseable is present.
//
//   - Modern: ``<license type="expression">MIT</license>`` or
//     ``<license type="expression">(MIT OR Apache-2.0)</license>``
//     → value as-is.  ``type="file"`` means the license text is
//     bundled inside the .nupkg; we record the value (a path)
//     and let server-side SPDX normalisation decide what to do
//     with it.
//   - Legacy: ``<licenseUrl>https://licenses.nuget.org/MIT</licenseUrl>``
//     → attempt to extract ``MIT`` from the well-known
//     ``licenses.nuget.org/<id>`` shape; otherwise return the
//     raw URL.  CVE correlation doesn't key off licence so
//     imperfect parsing is OK.
func extractLicense(m nuspecManifest) string {
	if v := strings.TrimSpace(m.Metadata.License.Value); v != "" {
		return v
	}
	if url := strings.TrimSpace(m.Metadata.LicenseURL); url != "" {
		// licenses.nuget.org/<id> → <id>.  Anything else returned
		// verbatim; server-side normalisation can see the URL.
		const prefix = "https://licenses.nuget.org/"
		if strings.HasPrefix(url, prefix) {
			return strings.TrimSuffix(url[len(prefix):], "/")
		}
		return url
	}
	return ""
}
