// Package nuget is the scanner plugin for the .NET / NuGet ecosystem.
// Emits one PackageRecord per package in the user's NuGet global
// packages folder.
//
// Coverage (v1): the global packages folder layout NuGet uses by
// default since v3 (2014) — ``$HOME/.nuget/packages/<id>/<version>/
// <id>.nuspec`` on Linux/macOS, ``%UserProfile%\.nuget\packages\...``
// on Windows.  Overridable via the ``NUGET_PACKAGES`` env var and
// ``globalPackagesFolder`` in NuGet.Config (only the env var
// override is honoured in v1; NuGet.Config parsing would require
// a proper Microsoft-XML schema reader with override precedence
// rules we're not going to re-implement).
//
// Deferred to v2 (tracked on ROADMAP.md):
//
//   - ``packages.config`` legacy layout used by pre-4.x / .NET
//     Framework projects where nupkg metadata lives in a
//     solution-local ``packages/`` dir.  Rare on modern .NET;
//     land when a customer hits it.
//   - Parsing ``NuGet.Config`` to honour the
//     ``globalPackagesFolder`` setting.  Env-var override is the
//     80% case.
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

// layoutGlobalPackages tags Environments from the global-
// packages-folder discoverer.  Currently the only layout; the
// v2 ``packages.config`` support will add a second.
const layoutGlobalPackages = "nuget-global-packages"

func init() {
	scanner.Register(Scanner{})
}

// Scanner implements scanner.RootScanner.  NuGet's global packages
// folder sits at a well-known path; walking the whole filesystem
// looking for ``.nuspec`` files would be wasteful given the
// volume of unrelated XML on a typical host.  We probe the fixed
// path instead (same pattern as the JVM plugin).
type Scanner struct{}

// EnvType — see EnvNuGet.
func (Scanner) EnvType() string { return EnvNuGet }

// DiscoverAll probes the NuGet global packages folder and emits
// an Environment for it if present.  Honours ``NUGET_PACKAGES``
// when set; otherwise uses the platform-default path.
//
// A missing path is NOT an error — the user may not have .NET
// installed.  The RootScanner interface returns
// ([]Environment, []ScanError); we use the error slice only for
// genuinely unexpected states (e.g. ``NUGET_PACKAGES`` set but
// the target isn't a directory).
func (Scanner) DiscoverAll(ctx context.Context) ([]scanner.Environment, []scanner.ScanError) {
	_ = ctx
	path, fromEnv := globalPackagesPath()
	if path == "" {
		return nil, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []scanner.ScanError{{
			Path:      path,
			EnvType:   EnvNuGet,
			Error:     fmt.Sprintf("stat nuget global packages: %v", err),
			Timestamp: time.Now().UTC(),
		}}
	}
	if !info.IsDir() {
		// An operator-set NUGET_PACKAGES pointing at a file is
		// a config bug worth surfacing — scanning a file as a
		// directory would produce zero records silently.
		if fromEnv {
			return nil, []scanner.ScanError{{
				Path:      path,
				EnvType:   EnvNuGet,
				Error:     "NUGET_PACKAGES is set but does not name a directory",
				Timestamp: time.Now().UTC(),
			}}
		}
		return nil, nil
	}
	return []scanner.Environment{{
		EnvType: EnvNuGet,
		Name:    layoutGlobalPackages,
		Path:    path,
	}}, nil
}

// Scan walks one global-packages folder (two levels deep:
// ``<id>/<version>/<id>.nuspec``) and emits one PackageRecord
// per nuspec we can parse.  Per-package failures (permission
// denied, malformed XML, symlink-refused) surface as ScanErrors.
func (Scanner) Scan(ctx context.Context, env scanner.Environment) ([]scanner.PackageRecord, []scanner.ScanError) {
	_ = ctx
	switch env.Name {
	case layoutGlobalPackages:
		return scanGlobalPackages(env.Path)
	default:
		return nil, []scanner.ScanError{{
			Path:      env.Path,
			EnvType:   EnvNuGet,
			Error:     fmt.Sprintf("unknown nuget layout: %q", env.Name),
			Timestamp: time.Now().UTC(),
		}}
	}
}

// globalPackagesPath returns the effective NuGet global packages
// folder for the current host + user, and a bool indicating
// whether the value came from the ``NUGET_PACKAGES`` env var
// (the bool drives the error-severity decision in DiscoverAll).
//
// Precedence: NUGET_PACKAGES > platform default.  NuGet.Config's
// ``globalPackagesFolder`` setting is NOT honoured in v1 — it
// would require parsing Microsoft's XML config format with its
// multi-file cascade + machine-wide-vs-user rules.  The env
// var covers every dev + CI case we've seen.
func globalPackagesPath() (string, bool) {
	if env := os.Getenv("NUGET_PACKAGES"); env != "" {
		return env, true
	}
	home := userHome()
	if home == "" {
		return "", false
	}
	// Both Windows and POSIX use the same relative layout —
	// ``.nuget/packages`` under the user profile.  filepath.Join
	// handles the separator per-OS, so one return path covers
	// every platform.
	return filepath.Join(home, ".nuget", "packages"), false
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
