// Package supplychain produces per-package SupplyChainSignal entries
// from local filesystem inspection. Each ecosystem-specific entrypoint
// walks the relevant install dir (node_modules, .m2/repository, etc.)
// and emits signals like postinstall scripts, missing signatures, or
// presence of npm sigstore provenance attestations.
package supplychain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
	"github.com/sentari-dev/sentari-agent/scanner/pathfilter"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// maxPackageJSONBytes caps any single “package.json“ read.  Mirrors
// scanner/npm/parser.go's local constant — a hostile node_modules
// dependency cannot use safeio's symlink-refusal + size cap to push
// arbitrary content into a scan payload.
const maxPackageJSONBytes = 4 << 20 // 4 MiB

// utf8BOM is the UTF-8 byte-order mark (EF BB BF). npm tolerates a
// BOM-prefixed package.json, but encoding/json rejects the leading U+FEFF,
// so a BOM'd manifest would otherwise parse-fail and silently emit no
// supply-chain signal. Strip it before Unmarshal, mirroring the same fix
// applied in scanner/licenses and scanner/npm.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

func stripBOM(b []byte) []byte {
	return bytes.TrimPrefix(b, utf8BOM)
}

// isInstalledPackageDir reports whether dir is the top-level directory of
// an installed npm package — i.e. a direct child of a node_modules dir
// (`node_modules/<pkg>`) or a scoped package's dir
// (`node_modules/@scope/<pkg>`). The scan root passed to
// DetectInNodeModules is treated as an implicit node_modules so a caller
// that passes `<project>/node_modules` works whether or not the walk
// origin is literally named "node_modules".
//
// package.json files nested DEEPER inside a package (subpath-export stub
// manifests, bundled test fixtures like
// `node_modules/foo/test/fixtures/bar/package.json`) are NOT installed
// packages and must not emit spurious signals. The walk still descends
// through them to reach any nested node_modules (npm's hoisting layout).
func isInstalledPackageDir(dir, root string) bool {
	parent := filepath.Dir(dir)
	// node_modules/<pkg> — parent is the scan root or any node_modules dir.
	if parent == root || filepath.Base(parent) == "node_modules" {
		return true
	}
	// node_modules/@scope/<pkg> — parent is a scope dir sitting directly
	// under the scan root or a node_modules dir.
	if strings.HasPrefix(filepath.Base(parent), "@") {
		grand := filepath.Dir(parent)
		if grand == root || filepath.Base(grand) == "node_modules" {
			return true
		}
	}
	return false
}

// DetectInNodeModules walks `nodeModulesRoot` (typically
// `<project>/node_modules`) and produces one or more signals per
// installed package. Detected signal types:
//
//   - postinstall_script | preinstall_script | install_script
//     (presence of a non-empty `scripts.{post,pre,install}` field in
//     package.json — agents emit informational-severity signals so the
//     server-side workspace UI can show "this package runs a script
//     on install").
//   - provenance_attested
//     (presence of a sibling `<pkg>.sigstore` / `.signature.json` file —
//     newer npm publishes carry sigstore attestation alongside the tgz
//     in the registry; once unpacked into node_modules, the attestation
//     file sits next to package.json).
//   - unsigned
//     (absence of the above — only emitted when scripts are present, to
//     avoid flooding the signal table with every package).
//
// Sub-package `node_modules` directories are traversed too (npm's
// hoisting model leaves nested node_modules in non-flat installs).
func DetectInNodeModules(ctx context.Context, nodeModulesRoot string) ([]deptree.SupplyChainSignal, error) {
	var signals []deptree.SupplyChainSignal

	walkErr := filepath.WalkDir(nodeModulesRoot, func(path string, d fs.DirEntry, err error) error {
		if ctx.Err() != nil {
			return fs.SkipAll
		}
		if err != nil {
			return nil
		}
		// Symlinks: skip dirs entirely, ignore file leaves.  Defends
		// against a node_modules entry symlinking to /etc or to an
		// attacker-controlled tree.
		if d.Type()&os.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() && pathfilter.ShouldSkipDir(path) {
			return filepath.SkipDir
		}
		if !d.IsDir() {
			return nil
		}
		// node_modules and @scope dirs are traversal waypoints, not package
		// dirs themselves — keep descending but don't read a manifest here.
		if d.Name() == "node_modules" || strings.HasPrefix(d.Name(), "@") {
			return nil
		}
		// Only a direct child of a node_modules dir (or a scoped
		// node_modules/@scope/<pkg>) is a real installed package. package.json
		// files nested deeper (subpath-export stubs, bundled test fixtures)
		// must not emit signals — but keep walking so a nested node_modules
		// (npm hoisting) is still reached.
		if !isInstalledPackageDir(path, nodeModulesRoot) {
			return nil
		}
		pkgJSON := filepath.Join(path, "package.json")
		raw, err := safeio.ReadFile(pkgJSON, maxPackageJSONBytes)
		if err != nil {
			return nil
		}
		var pj struct {
			Name    string            `json:"name"`
			Version string            `json:"version"`
			Scripts map[string]string `json:"scripts"`
		}
		if err := json.Unmarshal(stripBOM(raw), &pj); err != nil {
			return nil
		}
		if pj.Name == "" {
			return nil
		}

		attested := hasAttestationFile(path)
		hasScript := false
		for _, scriptName := range []string{"postinstall", "preinstall", "install"} {
			body, ok := pj.Scripts[scriptName]
			if !ok || strings.TrimSpace(body) == "" {
				continue
			}
			hasScript = true
			signalType := scriptName + "_script"
			signals = append(signals, deptree.SupplyChainSignal{
				PackageName:    pj.Name,
				PackageVersion: pj.Version,
				Ecosystem:      "npm",
				SignalType:     signalType,
				Severity:       "info",
				Source:         "agent-npm-scripts",
				Raw: map[string]interface{}{
					"script_body": body,
				},
			})
		}
		if attested {
			signals = append(signals, deptree.SupplyChainSignal{
				PackageName:    pj.Name,
				PackageVersion: pj.Version,
				Ecosystem:      "npm",
				SignalType:     "provenance_attested",
				Severity:       "info",
				Source:         "agent-npm-sigstore",
			})
		} else if hasScript {
			// Only emit "unsigned" when the package also runs a script —
			// elevates the risk signal and keeps signal volume manageable.
			signals = append(signals, deptree.SupplyChainSignal{
				PackageName:    pj.Name,
				PackageVersion: pj.Version,
				Ecosystem:      "npm",
				SignalType:     "unsigned",
				Severity:       "low",
				Source:         "agent-npm-sigstore",
			})
		}
		return nil
	})
	if walkErr != nil {
		return signals, fmt.Errorf("walk %s: %w", nodeModulesRoot, walkErr)
	}
	return signals, nil
}

func hasAttestationFile(pkgDir string) bool {
	for _, name := range []string{".signature.json", "package.sigstore.json", ".sigstore"} {
		if _, err := os.Stat(filepath.Join(pkgDir, name)); err == nil {
			return true
		}
	}
	return false
}
