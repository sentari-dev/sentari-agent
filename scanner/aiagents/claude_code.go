package aiagents

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// layoutClaudeCode tags Environments produced by the Claude-Code
// discoverer.  Each agent / skill / plugin directory becomes one
// Environment so the Scan() walker can iterate without having to
// know the exact on-disk shape up-front.
const layoutClaudeCode = "claude-code"

// claudeCodeRoot is the conventional directory Claude Code uses
// for user-level agents, skills, and plugins.  Anthropic-controlled
// so the layout is stable enough to hardcode here.
func claudeCodeRoot() string {
	home := userHome()
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".claude")
}

// discoverClaudeCode emits one Environment per sub-dir (agents,
// skills, plugins) that exists under ~/.claude.  We don't emit for
// the root itself because a fresh Claude Code install creates an
// empty ~/.claude and we don't want to surface that as "the user
// has zero AI agents configured" (confusingly empty record).
func discoverClaudeCode() []scanner.Environment {
	root := claudeCodeRoot()
	if root == "" || !dirExists(root) {
		return nil
	}
	var envs []scanner.Environment
	for _, sub := range []string{"agents", "skills", "plugins"} {
		p := filepath.Join(root, sub)
		if dirExists(p) {
			envs = append(envs, scanner.Environment{
				EnvType: EnvAIAgent,
				Name:    layoutClaudeCode,
				Path:    p,
			})
		}
	}
	return envs
}

// scanClaudeCode walks one of the claude subdirs and emits a
// PackageRecord per discovered item.  Each item's shape is:
//
//   agents/<name>.md            -> "agent:<name>"
//   skills/<name>/SKILL.md      -> "skill:<name>"
//   plugins/<name>/plugin.json  -> "plugin:<name>"
//
// These are configurations, not packages — Name reflects that by
// carrying a prefix so they don't collide with real package names
// on the server-side partition.  Version is left empty because the
// conventions don't carry one; operators correlating against the
// install_age detective rule can key off InstallDate (file mtime)
// to see when agents were added.
func scanClaudeCode(path string) ([]scanner.PackageRecord, []scanner.ScanError) {
	base := filepath.Base(path)
	var (
		records []scanner.PackageRecord
		errs    []scanner.ScanError
	)

	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, []scanner.ScanError{{
			Path:      path,
			EnvType:   EnvAIAgent,
			Error:     fmt.Sprintf("claude readdir: %v", err),
			Timestamp: time.Now().UTC(),
		}}
	}

	for _, e := range entries {
		name, ok, serr := claudeEntryName(base, path, e)
		if serr != nil {
			errs = append(errs, *serr)
			continue
		}
		if !ok {
			continue
		}
		installDate := ""
		if info, err := e.Info(); err == nil {
			installDate = info.ModTime().UTC().Format(time.RFC3339)
		}
		records = append(records, scanner.PackageRecord{
			Name:        name,
			EnvType:     EnvAIAgent,
			InstallPath: filepath.Join(path, e.Name()),
			Environment: path,
			InstallDate: installDate,
		})
	}
	return records, errs
}

// claudeEntryName decides whether a single dir-entry under a
// claude-code subdir is a valid item and returns the canonical
// record Name for it.  Keeps the per-subdir branching out of the
// main walker body.  Returns (name, ok, err):
//   - name: the prefixed record name, or ""
//   - ok:   true iff this entry should be emitted
//   - err:  non-nil for filesystem errors we want to surface
func claudeEntryName(subdir, dirPath string, e fs.DirEntry) (string, bool, *scanner.ScanError) {
	switch subdir {
	case "agents":
		// agents/<name>.md — files only; ignore stray directories.
		if e.IsDir() {
			return "", false, nil
		}
		if !strings.HasSuffix(e.Name(), ".md") {
			return "", false, nil
		}
		return "agent:" + strings.TrimSuffix(e.Name(), ".md"), true, nil

	case "skills":
		// skills/<name>/SKILL.md — emit when the SKILL.md exists.
		if !e.IsDir() {
			return "", false, nil
		}
		skillFile := filepath.Join(dirPath, e.Name(), "SKILL.md")
		if _, err := os.Stat(skillFile); err != nil {
			// Subdir without a SKILL.md isn't a valid skill;
			// silently skip rather than emit a ghost record.
			return "", false, nil
		}
		return "skill:" + e.Name(), true, nil

	case "plugins":
		// plugins/<name>/plugin.json — emit when the manifest exists.
		if !e.IsDir() {
			return "", false, nil
		}
		manifest := filepath.Join(dirPath, e.Name(), "plugin.json")
		if _, err := os.Stat(manifest); err != nil {
			return "", false, nil
		}
		return "plugin:" + e.Name(), true, nil
	}
	return "", false, nil
}
