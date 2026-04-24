package aiagents

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// layoutIDEExtensions tags Environments from the IDE-extension
// discoverer.  Scan() walks the given extensions directory and
// emits one PackageRecord per extension whose manifest publisher +
// name matches the known-AI list below.
const layoutIDEExtensions = "ide-extensions"

// maxExtensionManifestBytes caps a VS Code package.json read.
// Real manifests are a few KiB; 512 KiB covers the largest
// extension packs without letting a hostile manifest OOM us.
const maxExtensionManifestBytes = 512 * 1024

// knownAIExtensions is the allowlist of IDE extensions we care
// about surfacing.  Keyed as publisher.name so we can match without
// a free-text LLM check or a cloud feed.  Deliberately narrow: this
// scanner is about *AI* / *agent* surfaces, not every extension.
// Adding to this list is how the list grows — keep it explicit.
var knownAIExtensions = map[string]struct{}{
	// GitHub Copilot family.
	"github.copilot":                {},
	"github.copilot-chat":           {},
	"github.copilot-labs":           {},
	// Anthropic's Claude Code VS Code extension.
	"anthropic.claude-code":         {},
	"anthropic.claude-dev":          {},
	// Cursor's in-IDE agents (when run inside VS Code variants).
	"saoudrizwan.claude-dev":        {},
	"anysphere.cursor":              {},
	// Continue — open-source AI pair-programming.
	"continue.continue":             {},
	// Cline — autonomous coding agent.
	"saoudrizwan.cline":             {},
	// Codeium — AI autocomplete (now Windsurf).
	"codeium.codeium":               {},
	"codeium.windsurf":              {},
	// Sourcegraph Cody.
	"sourcegraph.cody-ai":           {},
	// TabNine.
	"tabnine.tabnine-vscode":        {},
	// Amazon Q / CodeWhisperer.
	"amazonwebservices.aws-toolkit-vscode": {},
	"amazonwebservices.amazon-q-vscode":    {},
	// JetBrains AI Assistant (when VS Code compat mode)
	"jetbrains.jetbrains-ai":        {},
}

// ideExtensionPaths returns the well-known extension directories
// across VS Code, Cursor, and VS Code family forks on the current
// host.  Missing paths are silently skipped — not every dev has
// every IDE installed.
func ideExtensionPaths() []string {
	home := userHome()
	if home == "" {
		return nil
	}
	return []string{
		filepath.Join(home, ".vscode", "extensions"),
		filepath.Join(home, ".vscode-insiders", "extensions"),
		filepath.Join(home, ".vscode-server", "extensions"), // Remote-SSH
		filepath.Join(home, ".cursor", "extensions"),
		filepath.Join(home, ".windsurf", "extensions"),
	}
}

// discoverIDEExtensions emits one Environment per extensions-root
// that exists.  Scan() then walks each and filters by publisher.name.
func discoverIDEExtensions() []scanner.Environment {
	var envs []scanner.Environment
	for _, p := range ideExtensionPaths() {
		if dirExists(p) {
			envs = append(envs, scanner.Environment{
				EnvType: EnvAIAgent,
				Name:    layoutIDEExtensions,
				Path:    p,
			})
		}
	}
	return envs
}

// extensionManifest is the subset of VS Code's package.json we
// consume.  The real manifest carries many more fields
// (activationEvents, contributes, …); we only need identity.
type extensionManifest struct {
	Publisher   string `json:"publisher"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	DisplayName string `json:"displayName"`
}

// scanIDEExtensions walks ``root`` one level deep (each extension
// lives in its own sub-dir) and emits a PackageRecord per directory
// whose manifest publisher.name is in the known-AI allowlist.
// Non-AI extensions are deliberately NOT emitted — this is a
// targeted "shadow AI" inventory, not an extension dump.
func scanIDEExtensions(root string) ([]scanner.PackageRecord, []scanner.ScanError) {
	var (
		records []scanner.PackageRecord
		errs    []scanner.ScanError
	)
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, []scanner.ScanError{{
			Path:      root,
			EnvType:   EnvAIAgent,
			Error:     fmt.Sprintf("ide extensions readdir: %v", err),
			Timestamp: time.Now().UTC(),
		}}
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(root, e.Name())
		manifest := filepath.Join(dir, "package.json")
		info, err := os.Stat(manifest)
		if err != nil {
			// No manifest = not a VS Code extension dir (maybe
			// a cache dir); skip silently.
			continue
		}
		if info.Size() > maxExtensionManifestBytes {
			errs = append(errs, scanner.ScanError{
				Path:      manifest,
				EnvType:   EnvAIAgent,
				Error:     fmt.Sprintf("manifest exceeds size cap: %d", info.Size()),
				Timestamp: time.Now().UTC(),
			})
			continue
		}
		data, err := os.ReadFile(manifest)
		if err != nil {
			errs = append(errs, scanner.ScanError{
				Path:      manifest,
				EnvType:   EnvAIAgent,
				Error:     fmt.Sprintf("manifest read: %v", err),
				Timestamp: time.Now().UTC(),
			})
			continue
		}
		var m extensionManifest
		if err := json.Unmarshal(data, &m); err != nil {
			errs = append(errs, scanner.ScanError{
				Path:      manifest,
				EnvType:   EnvAIAgent,
				Error:     fmt.Sprintf("manifest parse: %v", err),
				Timestamp: time.Now().UTC(),
			})
			continue
		}
		if m.Publisher == "" || m.Name == "" {
			continue
		}
		key := strings.ToLower(m.Publisher + "." + m.Name)
		if _, ok := knownAIExtensions[key]; !ok {
			continue
		}
		installDate := info.ModTime().UTC().Format(time.RFC3339)
		records = append(records, scanner.PackageRecord{
			Name:        "ide-ext:" + key,
			Version:     m.Version,
			InstallPath: dir,
			EnvType:     EnvAIAgent,
			Environment: root,
			InstallDate: installDate,
		})
	}
	return records, errs
}
