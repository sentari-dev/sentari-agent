package npm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// maxPackageJSONBytes caps any single ``package.json`` read.
// Real manifests are a few KiB; 1 MiB is conservative headroom
// against a hostile or corrupt file without letting one package
// OOM the scanner.
const maxPackageJSONBytes = 1 * 1024 * 1024

// packageManifest is the subset of package.json we consume.
// The real file carries many more fields (scripts, deps, config,
// engines); we only need identity.
type packageManifest struct {
	Name       string      `json:"name"`
	Version    string      `json:"version"`
	License    interface{} `json:"license"`  // string or object (SPDX-ish)
	Licenses   interface{} `json:"licenses"` // legacy: array of {type, url}
	Deprecated interface{} `json:"deprecated"`
}

// scanNodeModules walks one ``node_modules/`` directory one level
// deep, handles scoped packages (``@scope/pkg``) via a second
// level, and emits one PackageRecord per manifest we can parse.
//
// Symlink handling: directory entries whose type includes
// ``ModeSymlink`` are skipped explicitly here.  The generic
// walker normally refuses to descend into symlinked directories
// (see scanner/scanner.go), but the npm plugin returns
// Terminal=true on Match so the generic protection no longer
// applies once we're inside node_modules.  This is the
// documented reason pnpm-in-default-mode produces zero records:
// ``node_modules/<pkg>`` is a symlink into
// ``node_modules/.pnpm/<pkg>@<ver>/node_modules/<pkg>`` and we
// refuse to follow it.  Hoisted pnpm (``shamefully-hoist=true``)
// lays out real directories and works identically to npm
// classic.
func scanNodeModules(root string) ([]scanner.PackageRecord, []scanner.ScanError) {
	var (
		records []scanner.PackageRecord
		errs    []scanner.ScanError
	)

	entries, err := os.ReadDir(root)
	if err != nil {
		// Can't read the node_modules dir at all — one ScanError
		// at the root.  Distinct from per-package failures below.
		return nil, []scanner.ScanError{{
			Path:      root,
			EnvType:   EnvNpm,
			Error:     fmt.Sprintf("readdir node_modules: %v", err),
			Timestamp: time.Now().UTC(),
		}}
	}

	for _, e := range entries {
		// Skip symlinked directory entries explicitly — see
		// symlink-handling note above.
		if e.Type()&os.ModeSymlink != 0 {
			continue
		}
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		// .bin, .package-lock.json-shaped artefacts, .cache —
		// directories starting with ``.`` are never package dirs.
		if strings.HasPrefix(name, ".") {
			continue
		}
		if strings.HasPrefix(name, "@") {
			// Scoped namespace: scope + slash + package name.
			// One more level of directory walk to reach each
			// scoped package's manifest.  ``root`` passed through
			// so scoped records carry the same ``Environment``
			// value as their flat-laid siblings.
			scopeRecs, scopeErrs := scanScope(root, filepath.Join(root, name), name)
			records = append(records, scopeRecs...)
			errs = append(errs, scopeErrs...)
			continue
		}
		rec, err := parsePackageDir(root, filepath.Join(root, name))
		if err != nil {
			errs = append(errs, scanner.ScanError{
				Path:      filepath.Join(root, name),
				EnvType:   EnvNpm,
				Error:     err.Error(),
				Timestamp: time.Now().UTC(),
			})
			continue
		}
		if rec != nil {
			records = append(records, *rec)
		}
	}

	return records, errs
}

// scanScope walks one ``@scope/`` directory and emits records
// for each scoped package inside.  Split out so the main loop
// stays flat.  ``envRoot`` is the node_modules directory that
// kicked off the scan — passed through so emitted records carry
// a consistent ``Environment`` value regardless of whether
// they're in a ``@scope`` subtree.
func scanScope(envRoot, scopeDir, scopeName string) ([]scanner.PackageRecord, []scanner.ScanError) {
	entries, err := os.ReadDir(scopeDir)
	if err != nil {
		return nil, []scanner.ScanError{{
			Path:      scopeDir,
			EnvType:   EnvNpm,
			Error:     fmt.Sprintf("readdir scope %s: %v", scopeName, err),
			Timestamp: time.Now().UTC(),
		}}
	}
	var (
		records []scanner.PackageRecord
		errs    []scanner.ScanError
	)
	for _, e := range entries {
		// Same symlink filter as the outer walk — pnpm scoped
		// packages also land as symlinks into ``.pnpm/``.
		if e.Type()&os.ModeSymlink != 0 {
			continue
		}
		if !e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		rec, err := parsePackageDir(envRoot, filepath.Join(scopeDir, e.Name()))
		if err != nil {
			errs = append(errs, scanner.ScanError{
				Path:      filepath.Join(scopeDir, e.Name()),
				EnvType:   EnvNpm,
				Error:     err.Error(),
				Timestamp: time.Now().UTC(),
			})
			continue
		}
		if rec != nil {
			records = append(records, *rec)
		}
	}
	return records, errs
}

// parsePackageDir reads one package's manifest and returns a
// PackageRecord.  Returns (nil, nil) when the directory isn't a
// valid package (no package.json, missing name/version); the
// caller then skips it silently — this is the common case for
// stray/cache dirs inside node_modules.  A hard error (permission
// denied, malformed JSON, symlink-refused) returns (nil, err).
//
// ``envRoot`` is the node_modules dir that kicked off the scan.
// It's stamped on ``Environment`` so every record from the same
// node_modules tree carries one consistent value — flat
// packages, scoped packages, and (later) nested layouts all
// group together on the server-side dashboard.  Previously each
// scope had its own ``@scope`` Environment string which split
// records arbitrarily.
func parsePackageDir(envRoot, pkgDir string) (*scanner.PackageRecord, error) {
	manifest := filepath.Join(pkgDir, "package.json")
	// Single fd for both the content read and the mtime — no
	// path-based TOCTOU window, matches the pattern we use in
	// aiagents.
	data, mtime, err := safeio.ReadFileWithMTime(manifest, maxPackageJSONBytes)
	if err != nil {
		if os.IsNotExist(err) {
			// Not a package dir — silent skip.
			return nil, nil //nolint:nilnil // idiomatic here
		}
		return nil, fmt.Errorf("read package.json: %w", err)
	}
	var m packageManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse package.json: %w", err)
	}
	if m.Name == "" || m.Version == "" {
		// Manifest exists but lacks identity — treat as "not a
		// real package" and skip silently.  A private/workspace
		// root manifest often has no version; we don't want to
		// emit a ghost record for it.
		return nil, nil //nolint:nilnil
	}
	return &scanner.PackageRecord{
		Name:        m.Name,
		Version:     m.Version,
		InstallPath: pkgDir,
		EnvType:     EnvNpm,
		Environment: envRoot,
		LicenseRaw:  extractLicense(m),
		InstallDate: mtime.Format(time.RFC3339),
	}, nil
}

// extractLicense returns a best-effort string representation of
// the manifest's license field.  npm's license field accepts
// several shapes in the wild:
//
//   - string: ``"MIT"`` or SPDX expression ``"(MIT OR Apache-2.0)"``
//   - object: ``{"type": "MIT", "url": "..."}``
//   - array (legacy ``licenses`` key): ``[{"type": "MIT", "url": "..."}]``
//
// We extract the type/name into a single string for downstream
// SPDX normalisation.  "" when nothing parseable is present.
func extractLicense(m packageManifest) string {
	if m.License != nil {
		if s, ok := m.License.(string); ok {
			return s
		}
		if obj, ok := m.License.(map[string]interface{}); ok {
			if t, _ := obj["type"].(string); t != "" {
				return t
			}
		}
	}
	if arr, ok := m.Licenses.([]interface{}); ok && len(arr) > 0 {
		if obj, ok := arr[0].(map[string]interface{}); ok {
			if t, _ := obj["type"].(string); t != "" {
				return t
			}
		}
	}
	return ""
}
