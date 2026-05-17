// Package supplychain produces per-package SupplyChainSignal entries
// from local filesystem inspection. Each ecosystem-specific entrypoint
// walks the relevant install dir (node_modules, .m2/repository, etc.)
// and emits signals like postinstall scripts, missing signatures, or
// presence of npm sigstore provenance attestations.
package supplychain

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// maxPackageJSONBytes caps any single ``package.json`` read.  Mirrors
// scanner/npm/parser.go's local constant — a hostile node_modules
// dependency cannot use safeio's symlink-refusal + size cap to push
// arbitrary content into a scan payload.
const maxPackageJSONBytes = 4 << 20 // 4 MiB

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
func DetectInNodeModules(nodeModulesRoot string) ([]deptree.SupplyChainSignal, error) {
	var signals []deptree.SupplyChainSignal

	walkErr := filepath.WalkDir(nodeModulesRoot, func(path string, d fs.DirEntry, err error) error {
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
		if !d.IsDir() {
			return nil
		}
		// Each package dir contains its own package.json one level inside.
		// Scoped packages (@scope/name) sit at depth 2 under node_modules.
		if d.Name() == "node_modules" || strings.HasPrefix(d.Name(), "@") {
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
		if err := json.Unmarshal(raw, &pj); err != nil {
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
