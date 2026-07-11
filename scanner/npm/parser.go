package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// utf8BOM is the UTF-8 byte-order mark (EF BB BF). npm tolerates a
// BOM-prefixed package.json, but encoding/json rejects the leading U+FEFF,
// so a BOM'd manifest would parse-fail and the package would silently drop
// out of inventory. Strip it before Unmarshal, mirroring scanner/licenses.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

func stripBOM(b []byte) []byte {
	return bytes.TrimPrefix(b, utf8BOM)
}

// maxPackageJSONBytes caps any single `package.json` read.
// Real manifests are a few KiB; 1 MiB is conservative headroom
// against a hostile or corrupt file without letting one package
// OOM the scanner.
const maxPackageJSONBytes = 1 * 1024 * 1024

// maxNestedNodeModulesDepth bounds how far we descend into
// version-conflict `node_modules` nested inside a package dir
// (node_modules/a/node_modules/lodash).  Real trees rarely exceed
// two or three levels; the cap is a cheap guard against a
// pathological or hostile layout looping the walk.  The top-level
// scan is depth 0; each nested node_modules increments.  A tree
// deeper than the cap surfaces a ScanError rather than silently
// truncating.
const maxNestedNodeModulesDepth = 10

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

// scanNodeModules walks one `node_modules/` directory one level
// deep, handles scoped packages (`@scope/pkg`) via a second
// level, and emits one PackageRecord per manifest we can parse.
// Each package dir is additionally checked for a nested
// `node_modules` (npm's version-conflict layout) and recursed
// into, bounded by maxNestedNodeModulesDepth — `depth` is the
// current nesting level (0 at the top-level scan root).
//
// Symlink handling: directory entries whose type includes
// `ModeSymlink` are skipped explicitly here.  The generic
// walker normally refuses to descend into symlinked directories
// (see scanner/scanner.go), but the npm plugin returns
// Terminal=true on Match so the generic protection no longer
// applies once we're inside node_modules.  In pnpm default mode
// `node_modules/<pkg>` is a symlink into
// `node_modules/.pnpm/<pkg>@<ver>/node_modules/<pkg>` which we
// refuse to follow here — those packages are instead inventoried
// from the REAL store directories by scanPnpmStore (called at the
// end of this function).  Hoisted pnpm (`shamefully-hoist=true`)
// lays out real directories and works identically to npm
// classic.
func scanNodeModules(ctx context.Context, root string, depth int) ([]scanner.PackageRecord, []scanner.ScanError) {
	// Cancellation: a timed-out container sub-scan or operator Ctrl-C
	// must stop this recursion within one directory step rather than
	// descending an entire deep node_modules tree.  Surface it as a
	// typed ScanError so the partial result is self-describing.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, []scanner.ScanError{{
			Path:      root,
			EnvType:   EnvNpm,
			Error:     fmt.Sprintf("scan cancelled: %v", ctxErr),
			Timestamp: time.Now().UTC(),
		}}
	}
	if depth > maxNestedNodeModulesDepth {
		// Refuse to descend further — a tree this deep is either
		// pathological or hostile.  Surface it rather than
		// silently truncating so operators can audit.
		return nil, []scanner.ScanError{{
			Path:      root,
			EnvType:   EnvNpm,
			Error:     fmt.Sprintf("nested node_modules depth exceeds cap (%d)", maxNestedNodeModulesDepth),
			Timestamp: time.Now().UTC(),
		}}
	}

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
		// directories starting with `.` are never package dirs.
		if strings.HasPrefix(name, ".") {
			continue
		}
		if strings.HasPrefix(name, "@") {
			// Scoped namespace: scope + slash + package name.
			// One more level of directory walk to reach each
			// scoped package's manifest.  `root` passed through
			// so scoped records carry the same `Environment`
			// value as their flat-laid siblings.
			scopeRecs, scopeErrs := scanScope(ctx, root, filepath.Join(root, name), name, depth)
			records = append(records, scopeRecs...)
			errs = append(errs, scopeErrs...)
			continue
		}
		recs, perErrs := scanPackage(ctx, root, filepath.Join(root, name), depth)
		records = append(records, recs...)
		errs = append(errs, perErrs...)
	}

	// pnpm default mode: `node_modules/<pkg>` are symlinks into the
	// virtual store and were skipped by the symlink filter above, and the
	// store dir itself (`.pnpm`) is dot-prefixed so it's skipped too.  The
	// REAL package directories live at
	// `node_modules/.pnpm/<pkg>@<ver>/node_modules/<pkg>`; walk them so a
	// default-mode install is still inventoried.  Absent `.pnpm` (npm /
	// yarn / hoisted-pnpm layouts) this is a cheap no-op.
	storeRecs, storeErrs := scanPnpmStore(ctx, root)
	records = append(records, storeRecs...)
	errs = append(errs, storeErrs...)

	return records, errs
}

// pnpmStoreDirName is the virtual-store directory pnpm creates under
// node_modules in its default (symlinked) install mode.
const pnpmStoreDirName = ".pnpm"

// scanPnpmStore emits PackageRecords for a pnpm default-mode install by
// walking the REAL package directories in the virtual store at
// `node_modules/.pnpm/<pkg>@<ver>/node_modules/<pkg>`.
//
// This is the short-term inventory fix (tracked on ROADMAP.md): it yields
// package records so default-mode installs are no longer invisible, but
// NOT full symlink-resolving dep-tree fidelity — that still needs the
// `openat2 RESOLVE_BENEATH` resolve-then-verify path noted in the package
// doc.  Only the ONE real package directory in each store entry's
// `node_modules` is emitted; that entry's own dependencies are themselves
// symlinks into other store entries and are skipped by the symlink
// filter, so every real package is emitted exactly once (from its own
// store entry).  The store is flat, so no nested `node_modules` descent
// happens here.  `nmRoot` is the node_modules directory that kicked off
// the scan; it is stamped as `Environment` on every store record so they
// group with any hoisted siblings under one consistent value.
func scanPnpmStore(ctx context.Context, nmRoot string) ([]scanner.PackageRecord, []scanner.ScanError) {
	store := filepath.Join(nmRoot, pnpmStoreDirName)
	info, err := os.Lstat(store)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		// No REAL `.pnpm` store (missing, a file, or a planted symlink we
		// refuse to follow) — nothing to do.
		return nil, nil
	}
	entries, err := os.ReadDir(store)
	if err != nil {
		return nil, []scanner.ScanError{{
			Path:      store,
			EnvType:   EnvNpm,
			Error:     fmt.Sprintf("readdir .pnpm store: %v", err),
			Timestamp: time.Now().UTC(),
		}}
	}
	var (
		records []scanner.PackageRecord
		errs    []scanner.ScanError
	)
	for _, e := range entries {
		if ctxErr := ctx.Err(); ctxErr != nil {
			errs = append(errs, scanner.ScanError{
				Path:      store,
				EnvType:   EnvNpm,
				Error:     fmt.Sprintf("scan cancelled: %v", ctxErr),
				Timestamp: time.Now().UTC(),
			})
			return records, errs
		}
		// Each store entry is a real `<pkg>@<ver>` directory.  Refuse
		// symlinks (nothing in the store should be one) and skip files /
		// dot entries (e.g. a stray lockfile).
		if e.Type()&os.ModeSymlink != 0 || !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		inner := filepath.Join(store, e.Name(), "node_modules")
		recs, perErrs := scanPnpmStoreEntry(ctx, nmRoot, inner)
		records = append(records, recs...)
		errs = append(errs, perErrs...)
	}
	return records, errs
}

// scanPnpmStoreEntry walks one store entry's `node_modules` one level
// deep (a second level for `@scope/`) and emits a record for each REAL
// package directory.  The entry's dependency symlinks are skipped by the
// symlink filter; nested `node_modules` are NOT descended — the store is
// flat, each real package owns its own store entry.  `envRoot` is the
// originating node_modules dir, stamped on `Environment` (see
// parsePackageDir).
func scanPnpmStoreEntry(ctx context.Context, envRoot, innerNM string) ([]scanner.PackageRecord, []scanner.ScanError) {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return nil, []scanner.ScanError{{
			Path:      innerNM,
			EnvType:   EnvNpm,
			Error:     fmt.Sprintf("scan cancelled: %v", ctxErr),
			Timestamp: time.Now().UTC(),
		}}
	}
	info, err := os.Lstat(innerNM)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, nil
	}
	entries, err := os.ReadDir(innerNM)
	if err != nil {
		return nil, []scanner.ScanError{{
			Path:      innerNM,
			EnvType:   EnvNpm,
			Error:     fmt.Sprintf("readdir pnpm store entry: %v", err),
			Timestamp: time.Now().UTC(),
		}}
	}
	var (
		records []scanner.PackageRecord
		errs    []scanner.ScanError
	)
	for _, e := range entries {
		// Dependencies of the store entry are symlinks into other store
		// entries — skip them; only the entry's own package is real.
		if e.Type()&os.ModeSymlink != 0 || !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if strings.HasPrefix(e.Name(), "@") {
			// Scoped: one more real level to reach `@scope/<pkg>`.
			scopeDir := filepath.Join(innerNM, e.Name())
			scEntries, scErr := os.ReadDir(scopeDir)
			if scErr != nil {
				errs = append(errs, scanner.ScanError{
					Path:      scopeDir,
					EnvType:   EnvNpm,
					Error:     fmt.Sprintf("readdir scope %s: %v", e.Name(), scErr),
					Timestamp: time.Now().UTC(),
				})
				continue
			}
			for _, se := range scEntries {
				if se.Type()&os.ModeSymlink != 0 || !se.IsDir() || strings.HasPrefix(se.Name(), ".") {
					continue
				}
				records, errs = appendStorePackage(records, errs, envRoot, filepath.Join(scopeDir, se.Name()))
			}
			continue
		}
		records, errs = appendStorePackage(records, errs, envRoot, filepath.Join(innerNM, e.Name()))
	}
	return records, errs
}

// appendStorePackage parses one store package directory (no nested
// descent) and appends its record or a ScanError.  Shared by the flat
// and scoped store walks.
func appendStorePackage(
	records []scanner.PackageRecord,
	errs []scanner.ScanError,
	envRoot, pkgDir string,
) ([]scanner.PackageRecord, []scanner.ScanError) {
	rec, err := parsePackageDir(envRoot, pkgDir)
	switch {
	case err != nil:
		errs = append(errs, scanner.ScanError{
			Path:      pkgDir,
			EnvType:   EnvNpm,
			Error:     err.Error(),
			Timestamp: time.Now().UTC(),
		})
	case rec != nil:
		records = append(records, *rec)
	}
	return records, errs
}

// scanScope walks one `@scope/` directory and emits records
// for each scoped package inside.  Split out so the main loop
// stays flat.  `envRoot` is the node_modules directory that
// kicked off the scan — passed through so emitted records carry
// a consistent `Environment` value regardless of whether
// they're in a `@scope` subtree.  `depth` threads the current
// nesting level so scoped packages with a nested `node_modules`
// (`@scope/pkg/node_modules/...`) recurse under the same cap.
func scanScope(ctx context.Context, envRoot, scopeDir, scopeName string, depth int) ([]scanner.PackageRecord, []scanner.ScanError) {
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
		// packages also land as symlinks into `.pnpm/`.
		if e.Type()&os.ModeSymlink != 0 {
			continue
		}
		if !e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		recs, perErrs := scanPackage(ctx, envRoot, filepath.Join(scopeDir, e.Name()), depth)
		records = append(records, recs...)
		errs = append(errs, perErrs...)
	}
	return records, errs
}

// scanPackage parses one package directory into a record and then
// descends into any nested `node_modules` it carries.  npm resolves
// a version conflict by nesting a private `node_modules` inside the
// depending package (node_modules/a/node_modules/lodash) when it
// needs a version different from the hoisted top-level one; without
// this descent those conflicting versions are invisible.  The
// nested descent is independent of whether the parent manifest
// parsed cleanly — a package with an unreadable manifest can still
// hold real nested packages worth capturing.  `depth` is the
// current nesting level, forwarded to the recursion's cap check.
func scanPackage(ctx context.Context, envRoot, pkgDir string, depth int) ([]scanner.PackageRecord, []scanner.ScanError) {
	var (
		records []scanner.PackageRecord
		errs    []scanner.ScanError
	)
	rec, err := parsePackageDir(envRoot, pkgDir)
	switch {
	case err != nil:
		errs = append(errs, scanner.ScanError{
			Path:      pkgDir,
			EnvType:   EnvNpm,
			Error:     err.Error(),
			Timestamp: time.Now().UTC(),
		})
	case rec != nil:
		records = append(records, *rec)
	}
	nestedRecs, nestedErrs := scanNestedNodeModules(ctx, pkgDir, depth)
	records = append(records, nestedRecs...)
	errs = append(errs, nestedErrs...)
	return records, errs
}

// scanNestedNodeModules recurses into `<pkgDir>/node_modules` when
// present.  The nested dir must be a real directory: a symlinked
// `node_modules` is refused for the same reason the per-entry
// symlink filter refuses symlinked package dirs — a planted
// symlink could redirect the walk outside the tree (see the
// symlink-handling note on scanNodeModules).  The nested tree is
// its own scan root, so records it emits carry the nested
// `node_modules` path as their `Environment`.  Absence of a nested
// `node_modules` (the common case) is not an error.
func scanNestedNodeModules(ctx context.Context, pkgDir string, depth int) ([]scanner.PackageRecord, []scanner.ScanError) {
	nested := filepath.Join(pkgDir, "node_modules")
	info, err := os.Lstat(nested)
	if err != nil {
		// No nested node_modules (or unreadable) — nothing to do.
		return nil, nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// Refuse to follow a symlinked node_modules.
		return nil, nil
	}
	if !info.IsDir() {
		return nil, nil
	}
	return scanNodeModules(ctx, nested, depth+1)
}

// parsePackageDir reads one package's manifest and returns a
// PackageRecord.  Returns (nil, nil) when the directory isn't a
// valid package (no package.json, missing name/version); the
// caller then skips it silently — this is the common case for
// stray/cache dirs inside node_modules.  A hard error (permission
// denied, malformed JSON, symlink-refused) returns (nil, err).
//
// `envRoot` is the node_modules dir that kicked off the scan.
// It's stamped on `Environment` so every record from the same
// node_modules tree carries one consistent value — flat and
// scoped packages group together on the server-side dashboard.
// Previously each scope had its own `@scope` Environment string
// which split records arbitrarily.  A nested `node_modules` is a
// distinct tree scanned as its own root, so its packages carry
// the nested path as their `Environment` (see scanPackage).
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
	// Strip a leading UTF-8 BOM: npm tolerates a BOM-prefixed
	// package.json, but encoding/json rejects the leading U+FEFF and
	// the package would otherwise silently drop out of inventory.
	if err := json.Unmarshal(stripBOM(data), &m); err != nil {
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
//   - string: `"MIT"` or SPDX expression `"(MIT OR Apache-2.0)"`
//   - object: `{"type": "MIT", "url": "..."}`
//   - array (legacy `licenses` key): `[{"type": "MIT", "url": "..."}]`
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
