package nuget

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// maxNuspecBytes caps any single nuspec read.  Real manifests are
// a few KiB; 512 KiB is generous headroom without letting a
// hostile or corrupt file OOM us.
const maxNuspecBytes = 512 * 1024

// maxNuGetConfigBytes / maxPackagesConfigBytes cap the two XML config
// reads.  Both are tiny in practice (a few KiB); the generous caps
// bound a hostile or corrupt file without letting it OOM us.
const (
	maxNuGetConfigBytes    = 1 * 1024 * 1024
	maxPackagesConfigBytes = 4 * 1024 * 1024
)

// nuspecManifest is the subset of .nuspec XML we consume.  The
// real schema carries many more fields (dependencies, icon,
// readme, repository); identity fields are all we need.
//
// NuGet's license handling has two shapes in the wild:
//   - Modern: <license type="expression|file">EXPR-OR-PATH</license>
//   - Legacy: <licenseUrl>https://...</licenseUrl>
//
// We surface both into LicenseRaw via extractLicense().
type nuspecManifest struct {
	XMLName  xml.Name `xml:"package"`
	Metadata struct {
		ID      string `xml:"id"`
		Version string `xml:"version"`
		Authors string `xml:"authors"`
		License struct {
			Type  string `xml:"type,attr"`
			Value string `xml:",chardata"`
		} `xml:"license"`
		LicenseURL string `xml:"licenseUrl"`
	} `xml:"metadata"`
}

// scanGlobalPackages walks the NuGet global-packages folder and
// emits one PackageRecord per `<id>/<version>/<id>.nuspec` we
// find.  Layout:
//
//	<root>/
//	  newtonsoft.json/
//	    13.0.3/
//	      newtonsoft.json.nuspec
//	      newtonsoft.json.13.0.3.nupkg
//
// NuGet stores IDs lowercased on disk but the manifest carries
// the canonical casing (`Newtonsoft.Json`).  We use the
// manifest's casing for the record name so CVE correlation
// against OSV-nuget advisories matches.
//
// ctx cancellation is honoured per id-directory: a timed-out or
// Ctrl-C'd run stops within one directory step rather than churning
// through a large store, and surfaces a typed "scan cancelled"
// ScanError so the partial result is self-describing.  Mirrors the
// jvm/npm scanners.
func scanGlobalPackages(ctx context.Context, root string) ([]scanner.PackageRecord, []scanner.ScanError) {
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
		if ctxErr := ctx.Err(); ctxErr != nil {
			errs = append(errs, scanErr(root, fmt.Sprintf("scan cancelled: %v", ctxErr)))
			return records, errs
		}
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
			if ctxErr := ctx.Err(); ctxErr != nil {
				errs = append(errs, scanErr(idDir, fmt.Sprintf("scan cancelled: %v", ctxErr)))
				return records, errs
			}
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

// parsePackageVersionDir reads `<pkgDir>/<idDirName>.nuspec`
// and returns a PackageRecord.  NuGet names the nuspec after the
// lowercase package ID (`newtonsoft.json.nuspec`) not the
// manifest's canonical casing.  Returns (nil, nil) when the
// directory isn't a valid package (no nuspec, missing
// id/version); the common case for stray dirs.
//
// `envRoot` is the global-packages folder — stamped on
// `Environment` so every record from the same install groups
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
//   - Modern: `<license type="expression">MIT</license>` or
//     `<license type="expression">(MIT OR Apache-2.0)</license>`
//     → value as-is.  `type="file"` means the license text is
//     bundled inside the .nupkg; we record the value (a path)
//     and let server-side SPDX normalisation decide what to do
//     with it.
//   - Legacy: `<licenseUrl>https://licenses.nuget.org/MIT</licenseUrl>`
//     → attempt to extract `MIT` from the well-known
//     `licenses.nuget.org/<id>` shape; otherwise return the
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

// nugetConfig is the minimal subset of NuGet.Config we consume.  The
// real schema has many sections (packageSources, packageSourceMapping,
// bindingRedirects, …); we read only `config/globalPackagesFolder`.
//
//	<configuration>
//	  <config>
//	    <add key="globalPackagesFolder" value="/data/nuget-cache" />
//	  </config>
//	</configuration>
type nugetConfig struct {
	XMLName xml.Name `xml:"configuration"`
	Config  struct {
		Add []struct {
			Key   string `xml:"key,attr"`
			Value string `xml:"value,attr"`
		} `xml:"add"`
	} `xml:"config"`
}

// globalPackagesFolderFromConfig locates the user-level NuGet.Config,
// reads the `config/globalPackagesFolder` setting, and returns its
// resolved path (or "" when unset/absent).  Relative values are
// resolved against the config file's directory — NuGet's own rule.
//
// Only the user-level config is consulted (not Microsoft's full
// machine-wide-vs-solution-vs-user cascade); that covers the common
// redirect case (a CI cache dir, an air-gapped shared store) without
// re-implementing the whole config engine.  A config that exists but
// is unreadable or malformed surfaces a ScanError rather than being
// silently ignored — a redirect we can't read could hide the entire
// package inventory.
func globalPackagesFolderFromConfig() (string, []scanner.ScanError) {
	for _, cfgPath := range nugetConfigCandidates() {
		data, _, err := safeio.ReadFileWithMTime(cfgPath, maxNuGetConfigBytes)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", []scanner.ScanError{scanErr(cfgPath, fmt.Sprintf("read NuGet.Config: %v", err))}
		}
		var c nugetConfig
		if err := xml.Unmarshal(data, &c); err != nil {
			return "", []scanner.ScanError{scanErr(cfgPath, fmt.Sprintf("parse NuGet.Config: %v", err))}
		}
		for _, add := range c.Config.Add {
			if !strings.EqualFold(strings.TrimSpace(add.Key), "globalPackagesFolder") {
				continue
			}
			val := strings.TrimSpace(add.Value)
			if val == "" {
				continue
			}
			if !filepath.IsAbs(val) {
				val = filepath.Join(filepath.Dir(cfgPath), val)
			}
			return filepath.Clean(val), nil
		}
		// Config present but no globalPackagesFolder key — fall through
		// to the next candidate location.
	}
	return "", nil
}

// nugetConfigCandidates returns the user-level NuGet.Config paths to
// probe, most-specific first.
//
//   - Windows: %APPDATA%\NuGet\NuGet.Config
//   - Unix/macOS: $XDG_CONFIG_HOME/NuGet/NuGet.Config (or
//     ~/.config/NuGet/NuGet.Config), then the legacy
//     ~/.nuget/NuGet/NuGet.Config.
func nugetConfigCandidates() []string {
	if runtime.GOOS == "windows" {
		if appData := os.Getenv("APPDATA"); appData != "" {
			return []string{filepath.Join(appData, "NuGet", "NuGet.Config")}
		}
		return nil
	}
	home := userHome()
	if home == "" {
		return nil
	}
	var out []string
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		out = append(out, filepath.Join(xdg, "NuGet", "NuGet.Config"))
	} else {
		out = append(out, filepath.Join(home, ".config", "NuGet", "NuGet.Config"))
	}
	out = append(out, filepath.Join(home, ".nuget", "NuGet", "NuGet.Config"))
	return out
}

// packagesConfig is the legacy solution-local manifest listing the
// packages a project depends on.  Only id+version are load-bearing;
// the assemblies themselves live under a sibling `packages/` dir we
// don't resolve here.
//
//	<packages>
//	  <package id="Newtonsoft.Json" version="13.0.3" targetFramework="net472" />
//	  <package id="Serilog" version="3.1.1" />
//	</packages>
type packagesConfig struct {
	XMLName  xml.Name `xml:"packages"`
	Packages []struct {
		ID      string `xml:"id,attr"`
		Version string `xml:"version,attr"`
	} `xml:"package"`
}

// scanPackagesConfig parses one legacy packages.config into one
// PackageRecord per `<package id= version=>` entry.  There is no
// per-package install path in this layout, so InstallPath/Environment
// are stamped with the config file's directory (the solution/project
// root) — every record from the same file groups together server-side.
func scanPackagesConfig(configPath string) ([]scanner.PackageRecord, []scanner.ScanError) {
	data, mtime, err := safeio.ReadFileWithMTime(configPath, maxPackagesConfigBytes)
	if err != nil {
		return nil, []scanner.ScanError{scanErr(configPath, fmt.Sprintf("read packages.config: %v", err))}
	}
	var pc packagesConfig
	if err := xml.Unmarshal(data, &pc); err != nil {
		return nil, []scanner.ScanError{scanErr(configPath, fmt.Sprintf("parse packages.config: %v", err))}
	}
	projectRoot := filepath.Dir(configPath)
	installDate := mtime.Format(time.RFC3339)
	var records []scanner.PackageRecord
	for _, p := range pc.Packages {
		id := strings.TrimSpace(p.ID)
		ver := strings.TrimSpace(p.Version)
		if id == "" || ver == "" {
			continue
		}
		records = append(records, scanner.PackageRecord{
			Name:        id,
			Version:     ver,
			InstallPath: projectRoot,
			EnvType:     EnvNuGet,
			Environment: projectRoot,
			InstallDate: installDate,
		})
	}
	return records, nil
}
