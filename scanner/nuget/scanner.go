// Package nuget is the scanner plugin for the .NET / NuGet ecosystem.
// Emits one PackageRecord per package in the user's NuGet global
// packages folder, plus any legacy solution-local packages.config
// found at the scan root.
//
// Coverage:
//
//   - Global packages folder — the layout NuGet uses by default
//     since v3 (2014): `$HOME/.nuget/packages/<id>/<version>/
//     <id>.nuspec` on Linux/macOS, `%UserProfile%\.nuget\packages\...`
//     on Windows.  The effective folder is resolved with NuGet's own
//     precedence: `NUGET_PACKAGES` env var > NuGet.Config
//     `globalPackagesFolder` > platform default.  When
//     `globalPackagesFolder` redirects the store we scan that folder
//     as well so a redirected host is never a silent zero-package
//     false-negative.
//   - Legacy `packages.config` — the pre-4.x / .NET-Framework layout
//     where a project lists `<package id= version=>` entries in a
//     solution-local `packages.config`.  We probe for one at the scan
//     root only (no whole-filesystem walk — that would be wasteful
//     given the volume of unrelated XML on a typical host, and is
//     out of charter).  Nested per-project `packages.config` files
//     deeper in a solution tree are therefore not inventoried; the
//     root-level file is the common case for a scoped project scan.
//
// NuGet.Config parsing is deliberately minimal: we read only the
// `config/globalPackagesFolder` key from the user-level config, not
// Microsoft's full multi-file machine-wide-vs-user cascade.
//
// Server-side ecosystem mapping: env_type="nuget" →
// ecosystem="nuget" (OSV / PURL convention).
package nuget

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// EnvNuGet is the env_type every record from this plugin carries.
// Kept in sync with the server-side ENV_TYPE_TO_ECOSYSTEM table.
const EnvNuGet = "nuget"

// layoutGlobalPackages tags Environments from the global-packages-
// folder discoverer.  layoutPackagesConfig tags the legacy
// solution-local packages.config layout.
const (
	layoutGlobalPackages = "nuget-global-packages"
	layoutPackagesConfig = "nuget-packages-config"
)

func init() {
	scanner.Register(Scanner{})
}

// Scanner implements scanner.RootScanner.  NuGet's global packages
// folder sits at a well-known path; walking the whole filesystem
// looking for `.nuspec` files would be wasteful given the
// volume of unrelated XML on a typical host.  We probe the fixed
// path instead (same pattern as the JVM plugin).
type Scanner struct{}

// EnvType — see EnvNuGet.
func (Scanner) EnvType() string { return EnvNuGet }

// folderSource distinguishes where a candidate global-packages folder
// came from; it drives the error-vs-silent-skip decision in
// probeGlobalFolder (a misconfigured explicit source is worth
// surfacing, a missing platform default is not).
type folderSource int

const (
	srcEnv     folderSource = iota // NUGET_PACKAGES
	srcDefault                     // platform default under the user profile
	srcConfig                      // NuGet.Config globalPackagesFolder
)

// DiscoverAll probes for NuGet package stores and emits an Environment
// per distinct layout/location found.
//
//   - The global packages folder(s): `NUGET_PACKAGES` when set wins
//     outright; otherwise the platform default plus any
//     `globalPackagesFolder` redirect from NuGet.Config.
//   - A legacy `packages.config` at the scan root, if present.
//
// A missing path is NOT an error — the user may not have .NET
// installed.  The error slice is reserved for genuinely unexpected
// states: an explicit source (`NUGET_PACKAGES`, or a NuGet.Config
// `globalPackagesFolder`) that points at something we can't scan.
func (Scanner) DiscoverAll(ctx context.Context) ([]scanner.Environment, []scanner.ScanError) {
	var (
		envs []scanner.Environment
		errs []scanner.ScanError
		seen = map[string]bool{}
	)
	addEnv := func(e *scanner.Environment) {
		if e == nil {
			return
		}
		key := filepath.Clean(e.Path)
		if seen[key] {
			return
		}
		seen[key] = true
		envs = append(envs, *e)
	}

	gEnvs, gErrs := discoverGlobalPackages()
	for i := range gEnvs {
		addEnv(&gEnvs[i])
	}
	errs = append(errs, gErrs...)

	pEnvs, pErrs := discoverPackagesConfig(scanner.ScanRootFromContext(ctx))
	for i := range pEnvs {
		addEnv(&pEnvs[i])
	}
	errs = append(errs, pErrs...)

	return envs, errs
}

// discoverGlobalPackages resolves the effective global-packages
// folder(s) with NuGet precedence and probes each.
func discoverGlobalPackages() ([]scanner.Environment, []scanner.ScanError) {
	// NUGET_PACKAGES wins entirely (NuGet precedence): when set it is
	// the sole global-packages folder — NuGet.Config's
	// globalPackagesFolder and the platform default are both ignored.
	if env := os.Getenv("NUGET_PACKAGES"); env != "" {
		e, se := probeGlobalFolder(env, srcEnv)
		return oneOrNone(e, se)
	}

	var (
		envs []scanner.Environment
		errs []scanner.ScanError
	)
	if def := defaultGlobalPackages(); def != "" {
		if e, se := probeGlobalFolder(def, srcDefault); e != nil {
			envs = append(envs, *e)
		} else if se != nil {
			errs = append(errs, *se)
		}
	}

	cfgFolder, cfgErrs := globalPackagesFolderFromConfig()
	errs = append(errs, cfgErrs...)
	if cfgFolder != "" {
		if e, se := probeGlobalFolder(cfgFolder, srcConfig); e != nil {
			envs = append(envs, *e)
		} else if se != nil {
			errs = append(errs, *se)
		}
	}
	return envs, errs
}

// oneOrNone wraps a single probe result into the slice-pair shape.
func oneOrNone(e *scanner.Environment, se *scanner.ScanError) ([]scanner.Environment, []scanner.ScanError) {
	var (
		envs []scanner.Environment
		errs []scanner.ScanError
	)
	if e != nil {
		envs = append(envs, *e)
	}
	if se != nil {
		errs = append(errs, *se)
	}
	return envs, errs
}

// probeGlobalFolder stats one candidate global-packages folder and
// decides whether it becomes an Environment, a ScanError, or a silent
// skip.  An explicit source (env var / NuGet.Config) that points at a
// non-directory or unreadable/absent target surfaces a ScanError
// rather than a silent zero-package result; a missing platform
// default is expected (no .NET installed) and stays silent.
func probeGlobalFolder(path string, src folderSource) (*scanner.Environment, *scanner.ScanError) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			// A configured redirect that doesn't exist is a config bug
			// worth surfacing; an absent env-var target or default is not.
			if src == srcConfig {
				e := scanErr(path, "NuGet.Config globalPackagesFolder does not exist")
				return nil, &e
			}
			return nil, nil
		}
		e := scanErr(path, fmt.Sprintf("stat nuget global packages: %v", err))
		return nil, &e
	}
	if !info.IsDir() {
		switch src {
		case srcEnv:
			// An operator-set NUGET_PACKAGES pointing at a file is a
			// config bug worth surfacing — scanning a file as a
			// directory would produce zero records silently.
			e := scanErr(path, "NUGET_PACKAGES is set but does not name a directory")
			return nil, &e
		case srcConfig:
			e := scanErr(path, "NuGet.Config globalPackagesFolder is not a directory")
			return nil, &e
		default:
			return nil, nil
		}
	}
	return &scanner.Environment{
		EnvType: EnvNuGet,
		Name:    layoutGlobalPackages,
		Path:    path,
	}, nil
}

// discoverPackagesConfig probes for a legacy solution-local
// packages.config at the scan root.  It deliberately does NOT walk the
// filesystem (charter): only the root-level file is inventoried.  A
// full-system root (`/` or a bare drive letter) is skipped — a
// root-level packages.config there would be meaningless noise.
func discoverPackagesConfig(scanRoot string) ([]scanner.Environment, []scanner.ScanError) {
	if scanRoot == "" {
		return nil, nil
	}
	clean := filepath.Clean(scanRoot)
	if clean == "/" || (runtime.GOOS == "windows" && len(clean) <= 3) {
		return nil, nil
	}
	cfgPath := filepath.Join(clean, "packages.config")
	info, err := os.Stat(cfgPath)
	if err != nil {
		// Absent (or unreadable) → nothing to inventory; not an error.
		return nil, nil
	}
	if info.IsDir() {
		return nil, nil
	}
	return []scanner.Environment{{
		EnvType: EnvNuGet,
		Name:    layoutPackagesConfig,
		Path:    cfgPath,
	}}, nil
}

// Scan dispatches on the layout tag stamped during discovery.
func (Scanner) Scan(ctx context.Context, env scanner.Environment) ([]scanner.PackageRecord, []scanner.ScanError) {
	switch env.Name {
	case layoutGlobalPackages:
		return scanGlobalPackages(ctx, env.Path)
	case layoutPackagesConfig:
		return scanPackagesConfig(env.Path)
	default:
		return nil, []scanner.ScanError{scanErr(env.Path, fmt.Sprintf("unknown nuget layout: %q", env.Name))}
	}
}

// defaultGlobalPackages returns the platform-default NuGet global
// packages folder for the current user, or "" when the home directory
// can't be resolved.
//
// Both Windows and POSIX use the same relative layout —
// `.nuget/packages` under the user profile.  filepath.Join handles the
// separator per-OS, so one return path covers every platform.
func defaultGlobalPackages() string {
	home := userHome()
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".nuget", "packages")
}

// userHome — platform-appropriate home lookup.  Kept local to the
// plugin (same shape as scanner/jvm + scanner/aiagents) so each
// plugin's import surface stays small and auditable.
func userHome() string {
	if runtime.GOOS == "windows" {
		if up := os.Getenv("USERPROFILE"); up != "" {
			return up
		}
	}
	return os.Getenv("HOME")
}

// scanErr builds a NuGet-tagged ScanError with a current timestamp.
func scanErr(path, msg string) scanner.ScanError {
	return scanner.ScanError{
		Path:      path,
		EnvType:   EnvNuGet,
		Error:     msg,
		Timestamp: time.Now().UTC(),
	}
}
