package gobinaries

import (
	"fmt"
	"runtime/debug"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// stdlibModuleName is the conventional name under which the Go standard
// library is tracked (the Go vulnerability database keys toolchain CVEs on a
// module literally named "stdlib"). One such record is emitted per binary
// carrying its GoVersion verbatim.
const stdlibModuleName = "stdlib"

// develVersion is the placeholder version the Go toolchain records for a
// locally-built main module that has no released version.
const develVersion = "(devel)"

// maxModulesPerBinary bounds the number of module records a single binary may
// contribute. Real dependency lists are far below this; a value beyond it
// signals a crafted or corrupt buildinfo section. On overflow the records are
// truncated and a ScanError names the cap. A var so tests can lower it.
var maxModulesPerBinary = 4096

// recordsFromBuildInfo converts a parsed debug.BuildInfo into one
// PackageRecord per embedded module: the main module (version-repaired), each
// dependency (replace-directives resolved to the replacement), and a single
// stdlib record carrying the toolchain version. It is pure — no I/O, no clock;
// ScanError timestamps are left zero for the caller to stamp at the package
// boundary.
func recordsFromBuildInfo(bi *debug.BuildInfo, binPath string) ([]scanner.PackageRecord, []scanner.ScanError) {
	if bi == nil {
		return nil, nil
	}

	var (
		records []scanner.PackageRecord
		errs    []scanner.ScanError
	)

	emit := func(name, version string) bool {
		if name == "" {
			return true // skip nameless entries, never fabricate an identity
		}
		if len(records) >= maxModulesPerBinary {
			return false
		}
		records = append(records, scanner.PackageRecord{
			Name:        name,
			Version:     version,
			EnvType:     EnvGoBinary,
			InstallPath: binPath,
			Environment: binPath,
		})
		return true
	}

	capped := false

	// Main module first — the most valuable record (it names the product).
	mainVer := mainModuleVersion(bi)
	if !emit(bi.Main.Path, mainVer) {
		capped = true
	}

	// Dependencies, replace-directives resolved to the replacement.
	if !capped {
		for _, dep := range bi.Deps {
			if dep == nil {
				continue
			}
			mod := dep
			if dep.Replace != nil {
				mod = dep.Replace
			}
			if !emit(mod.Path, mod.Version) {
				capped = true
				break
			}
		}
	}

	// Standard library / toolchain record, keyed on GoVersion.
	if !capped {
		if !emit(stdlibModuleName, bi.GoVersion) {
			capped = true
		}
	}

	if capped {
		errs = append(errs, scanner.ScanError{
			Path:    binPath,
			EnvType: EnvGoBinary,
			Error:   fmt.Sprintf("module count exceeds cap of %d; remaining modules skipped", maxModulesPerBinary),
		})
	}

	return records, errs
}

// mainModuleVersion returns the version to record for the main module. A
// released main module (go install mod@vX.Y.Z) carries a real version and is
// returned verbatim. A locally-built main module reports "(devel)"; when a
// vcs.revision build setting is present it is substituted (truthful, immutable
// commit identity), otherwise "(devel)" is preserved rather than inventing an
// identity. vcs.modified ("dirty") is deliberately not encoded — no format
// invention.
func mainModuleVersion(bi *debug.BuildInfo) string {
	v := bi.Main.Version
	if v != develVersion && v != "" {
		return v
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			return s.Value
		}
	}
	return v
}
