// Package scanner: v3 payload enrichment.
//
// enrichWithV3 is a purely-additive Phase-3 hook that augments a
// completed v2 ScanResult with the four new payload sections:
//
//   - DepEdges            (per-lockfile dep-graph edges)
//   - Lockfiles           (lockfile metadata for drift detection)
//   - SupplyChainSignals  (postinstall scripts, unsigned artefacts, yanked pkgs)
//   - LicenseEvidence     (per-package license discovery)
//
// Design notes:
//
//   - Every module call is wrapped in error-tolerant logging.  A
//     parser panic or a single malformed lockfile must never abort
//     the v2 scan path — the scan is already complete when this
//     runs, and the worst case is "v3 sections empty for this host".
//
//   - Maven (~/.m2/repository) and NuGet (~/.nuget/packages) caches
//     are user-global, not per-project.  They're walked once per
//     scan invocation, not per detected root.
//
//   - PyPI license / supply-chain extraction needs a site-packages
//     directory.  Lockfile discovery only points us at the project
//     root (where Pipfile.lock / poetry.lock / requirements.txt
//     lives), so we probe common venv layouts under each root:
//     ``.venv/lib/python*/site-packages``, ``venv/lib/python*/site-packages``.
//     If none exists this just skips silently — the v2 pip/poetry/pipenv
//     scanners already covered the real venv via the marker walker.
//
//   - Each scan root is treated as a candidate "project root tree" and
//     handed to lockfiles.DiscoverInRoot, which already implements the
//     skip rules (node_modules, target, .git, etc.) needed to keep the
//     walk cheap on large filesystems.
package scanner

import (
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
	"github.com/sentari-dev/sentari-agent/scanner/licenses"
	"github.com/sentari-dev/sentari-agent/scanner/lockfiles"
	"github.com/sentari-dev/sentari-agent/scanner/supplychain"
)

// v3DiscoveryRoots returns the list of filesystem roots that should
// be walked for lockfile discovery.
//
// When scanRoot is a real bounded path (e.g. an operator-pinned
// project directory or a test tempdir), it is returned verbatim
// — the scanner respects the caller's scope.
//
// When scanRoot is the filesystem root (``/`` on POSIX or a drive
// root on Windows), we substitute user home directories.  Walking
// ``/`` for lockfiles would be prohibitively expensive on hosts
// with deep system trees, and the resulting matches under
// ``/proc``, ``/var``, etc. are almost always noise; user homes
// are where developer projects actually live.
func v3DiscoveryRoots(scanRoot string) []string {
	clean := filepath.Clean(scanRoot)
	if clean == "/" || (runtime.GOOS == "windows" && len(clean) <= 3) {
		return userHomeDirs()
	}
	return []string{scanRoot}
}

// enrichWithV3 augments result with the four v3 payload sections.
//
// roots is the list of filesystem trees to discover lockfiles under
// (typically the scanner's configured ScanRoot plus any extra roots
// the caller knows about).  The function is best-effort: per-module
// failures are logged and the scan continues.
//
// This function does NOT mutate the v2-shape ScanResult fields
// (Packages, Errors, etc.) — those have already been populated by
// Runner.Run before enrichWithV3 is invoked.
func enrichWithV3(result *ScanResult, roots []string) {
	if result == nil {
		return
	}

	// Track which project roots host an npm/pnpm/yarn lockfile so we
	// know which node_modules trees to feed to the npm supplychain +
	// licenses extractors.  Key: directory containing the lockfile.
	npmProjectDirs := make(map[string]struct{})
	// Same idea for PyPI: directories holding Pipfile.lock / poetry.lock /
	// uv.lock / requirements.txt are likely candidates for a sibling
	// venv whose site-packages we can introspect.
	pypiProjectDirs := make(map[string]struct{})

	// Phase 1: per-root lockfile discovery + per-lockfile dep-tree parsing.
	for _, root := range roots {
		if root == "" {
			continue
		}
		metas, err := lockfiles.DiscoverInRoot(root)
		if err != nil {
			slog.Warn("v3 lockfile discovery encountered errors", "root", root, "err", err.Error())
			// Non-fatal — metas may still contain partial results.
		}
		result.Lockfiles = append(result.Lockfiles, metas...)

		for _, meta := range metas {
			dir := filepath.Dir(meta.Path)
			switch meta.Format {
			case "package_lock_v2", "package_lock_v3":
				npmProjectDirs[dir] = struct{}{}
				if edges, err := deptree.ParseNpmPackageLock(meta.Path); err != nil {
					slog.Warn("v3 npm package-lock parse failed", "path", meta.Path, "err", err.Error())
				} else {
					result.DepEdges = append(result.DepEdges, edges...)
				}
			case "yarn_v1":
				npmProjectDirs[dir] = struct{}{}
				pkgJSON := filepath.Join(dir, "package.json")
				if edges, err := deptree.ParseYarnLock(meta.Path, pkgJSON); err != nil {
					slog.Warn("v3 yarn lock parse failed", "path", meta.Path, "err", err.Error())
				} else {
					result.DepEdges = append(result.DepEdges, edges...)
				}
			case "pnpm_lock":
				npmProjectDirs[dir] = struct{}{}
				if edges, err := deptree.ParsePnpmLock(meta.Path); err != nil {
					slog.Warn("v3 pnpm lock parse failed", "path", meta.Path, "err", err.Error())
				} else {
					result.DepEdges = append(result.DepEdges, edges...)
				}
			case "pom_xml":
				if home, herr := os.UserHomeDir(); herr == nil {
					m2 := filepath.Join(home, ".m2", "repository")
					if edges, err := deptree.ParseMavenPom(meta.Path, m2); err != nil {
						slog.Warn("v3 maven pom parse failed", "path", meta.Path, "err", err.Error())
					} else {
						result.DepEdges = append(result.DepEdges, edges...)
					}
				}
			case "project_assets_json":
				if edges, err := deptree.ParseNuGetProjectAssets(meta.Path); err != nil {
					slog.Warn("v3 nuget project.assets parse failed", "path", meta.Path, "err", err.Error())
				} else {
					result.DepEdges = append(result.DepEdges, edges...)
				}
			case "uv_lock":
				pypiProjectDirs[dir] = struct{}{}
				if edges, err := deptree.ParseUvLock(meta.Path); err != nil {
					slog.Warn("v3 uv.lock parse failed", "path", meta.Path, "err", err.Error())
				} else {
					result.DepEdges = append(result.DepEdges, edges...)
				}
			case "poetry_lock":
				pypiProjectDirs[dir] = struct{}{}
				if edges, err := deptree.ParsePoetryLock(meta.Path); err != nil {
					slog.Warn("v3 poetry.lock parse failed", "path", meta.Path, "err", err.Error())
				} else {
					result.DepEdges = append(result.DepEdges, edges...)
				}
			case "pipfile_lock":
				pypiProjectDirs[dir] = struct{}{}
				if edges, err := deptree.ParsePipfileLock(meta.Path); err != nil {
					slog.Warn("v3 Pipfile.lock parse failed", "path", meta.Path, "err", err.Error())
				} else {
					result.DepEdges = append(result.DepEdges, edges...)
				}
			case "requirements_txt":
				pypiProjectDirs[dir] = struct{}{}
				if edges, err := deptree.ParseRequirementsTxt(meta.Path); err != nil {
					slog.Warn("v3 requirements.txt parse failed", "path", meta.Path, "err", err.Error())
				} else {
					result.DepEdges = append(result.DepEdges, edges...)
				}
			case "packages_lock_json":
				// No dep-tree parser for packages.lock.json yet — the
				// project.assets.json sibling (always present after
				// `dotnet restore`) carries the resolved graph and is
				// handled by the project_assets_json case above.  The
				// lockfile metadata itself is still recorded.
			}
		}
	}

	// Phase 2: npm node_modules — per-project supply-chain + license extraction.
	for dir := range npmProjectDirs {
		nm := filepath.Join(dir, "node_modules")
		st, err := os.Stat(nm)
		if err != nil || !st.IsDir() {
			continue
		}
		if signals, err := supplychain.DetectInNodeModules(nm); err != nil {
			slog.Warn("v3 npm supply-chain detection failed", "node_modules", nm, "err", err.Error())
		} else {
			result.SupplyChainSignals = append(result.SupplyChainSignals, signals...)
		}
		if evidence, err := licenses.ExtractNpm(nm); err != nil {
			slog.Warn("v3 npm license extraction failed", "node_modules", nm, "err", err.Error())
		} else {
			result.LicenseEvidence = append(result.LicenseEvidence, evidence...)
		}
	}

	// Phase 3: PyPI venv site-packages — best-effort under each project dir.
	for dir := range pypiProjectDirs {
		for _, sp := range candidateSitePackages(dir) {
			if signals, err := supplychain.DetectInPipCache(sp); err != nil {
				slog.Warn("v3 pypi supply-chain detection failed", "site_packages", sp, "err", err.Error())
			} else {
				result.SupplyChainSignals = append(result.SupplyChainSignals, signals...)
			}
			if evidence, err := licenses.ExtractPyPI(sp); err != nil {
				slog.Warn("v3 pypi license extraction failed", "site_packages", sp, "err", err.Error())
			} else {
				result.LicenseEvidence = append(result.LicenseEvidence, evidence...)
			}
		}
	}

	// Phase 4: user-global Maven + NuGet caches — once per scan run.
	if home, err := os.UserHomeDir(); err == nil {
		m2 := filepath.Join(home, ".m2", "repository")
		if st, err := os.Stat(m2); err == nil && st.IsDir() {
			if signals, err := supplychain.DetectInM2(m2); err != nil {
				slog.Warn("v3 maven supply-chain detection failed", "m2", m2, "err", err.Error())
			} else {
				result.SupplyChainSignals = append(result.SupplyChainSignals, signals...)
			}
			if evidence, err := licenses.ExtractMaven(m2); err != nil {
				slog.Warn("v3 maven license extraction failed", "m2", m2, "err", err.Error())
			} else {
				result.LicenseEvidence = append(result.LicenseEvidence, evidence...)
			}
		}
		nuget := filepath.Join(home, ".nuget", "packages")
		if st, err := os.Stat(nuget); err == nil && st.IsDir() {
			if signals, err := supplychain.DetectInNuGetCache(nuget); err != nil {
				slog.Warn("v3 nuget supply-chain detection failed", "cache", nuget, "err", err.Error())
			} else {
				result.SupplyChainSignals = append(result.SupplyChainSignals, signals...)
			}
			if evidence, err := licenses.ExtractNuGet(nuget); err != nil {
				slog.Warn("v3 nuget license extraction failed", "cache", nuget, "err", err.Error())
			} else {
				result.LicenseEvidence = append(result.LicenseEvidence, evidence...)
			}
		}
	}
}

// candidateSitePackages returns plausible site-packages dirs under
// projectDir for the common venv layouts.  Only existing dirs are
// returned.  Cross-platform: handles both POSIX
// (``lib/pythonX.Y/site-packages``) and Windows
// (``Lib/site-packages``) layouts.
func candidateSitePackages(projectDir string) []string {
	var out []string
	for _, venvName := range []string{".venv", "venv", "env"} {
		venv := filepath.Join(projectDir, venvName)
		st, err := os.Stat(venv)
		if err != nil || !st.IsDir() {
			continue
		}
		// Windows layout.
		winSP := filepath.Join(venv, "Lib", "site-packages")
		if s, err := os.Stat(winSP); err == nil && s.IsDir() {
			out = append(out, winSP)
		}
		// POSIX layout: <venv>/lib/pythonX.Y/site-packages.
		libDir := filepath.Join(venv, "lib")
		entries, err := os.ReadDir(libDir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() || !strings.HasPrefix(e.Name(), "python") {
				continue
			}
			sp := filepath.Join(libDir, e.Name(), "site-packages")
			if s, err := os.Stat(sp); err == nil && s.IsDir() {
				out = append(out, sp)
			}
		}
	}
	return out
}
