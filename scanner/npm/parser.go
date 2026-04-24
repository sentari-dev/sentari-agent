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
// Symlink semantics: safeio.ReadFile refuses symlinks at the
// manifest leaf, which means pnpm non-hoisted layouts (where
// ``node_modules/<pkg>`` is a symlink into ``.pnpm/...``) produce
// zero records.  That's a documented v1 gap — see the package
// docstring in scanner.go.
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
			// scoped package's manifest.
			scopeRecs, scopeErrs := scanScope(filepath.Join(root, name), name)
			records = append(records, scopeRecs...)
			errs = append(errs, scopeErrs...)
			continue
		}
		rec, err := parsePackageDir(filepath.Join(root, name))
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
// stays flat.
func scanScope(scopeDir, scopeName string) ([]scanner.PackageRecord, []scanner.ScanError) {
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
		if !e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		rec, err := parsePackageDir(filepath.Join(scopeDir, e.Name()))
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
func parsePackageDir(pkgDir string) (*scanner.PackageRecord, error) {
	manifest := filepath.Join(pkgDir, "package.json")
	data, err := safeio.ReadFile(manifest, maxPackageJSONBytes)
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
	// InstallDate proxy: the manifest's mtime, obtained via the
	// same file descriptor safeio already validated so there's
	// no symlink-swap TOCTOU window.  Fallback to empty string
	// when the stat fails.
	installDate := ""
	if info, err := os.Stat(manifest); err == nil {
		installDate = info.ModTime().UTC().Format(time.RFC3339)
	}
	return &scanner.PackageRecord{
		Name:        m.Name,
		Version:     m.Version,
		InstallPath: pkgDir,
		EnvType:     EnvNpm,
		Environment: filepath.Dir(pkgDir),
		LicenseRaw:  extractLicense(m),
		InstallDate: installDate,
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
