package aiagents

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// layoutMCPConfig tags every Environment produced by the MCP-config
// discoverer.  Scan() dispatches on this to the matching walker.
const layoutMCPConfig = "mcp-config"

// maxMCPConfigBytes caps any single mcp.json read.  Real configs
// are a few KiB; 256 KiB is generous headroom against a hostile
// or corrupted file.
const maxMCPConfigBytes = 256 * 1024

// mcpConfigShape is the subset of a claude_desktop_config.json /
// mcp.json we consume.  The real files carry more keys (window
// position, UI preferences); we only need the mcpServers map.
type mcpConfigShape struct {
	MCPServers map[string]mcpServerEntry `json:"mcpServers"`
}

// mcpServerEntry is one configured MCP server.  The ``command`` +
// ``args`` pair is what gets launched; for attribution we capture
// both so operators can tell "this is the github-mcp-server" apart
// from "this is a custom Python script calling itself github".
type mcpServerEntry struct {
	Command string            `json:"command"`
	Args    []string          `json:"args"`
	Env     map[string]string `json:"env"`
}

// discoverMCPConfigs enumerates the platform-appropriate MCP config
// paths and emits one Environment per config file that exists.
//
// Error semantics (aligning with the comment the review found
// outdated): os.IsNotExist is silently skipped — the user simply
// doesn't have that tool configured.  Permission-denied is
// returned as a ScanError alongside the envs so operators can
// tell "not installed" from "agent can't read this user's config"
// via the exit surface, not by grepping stderr.
func discoverMCPConfigs() ([]scanner.Environment, []scanner.ScanError) {
	var envs []scanner.Environment
	var errs []scanner.ScanError
	for _, path := range mcpConfigPaths() {
		info, err := os.Stat(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			errs = append(errs, scanner.ScanError{
				Path:      path,
				EnvType:   EnvAIAgent,
				Error:     fmt.Sprintf("mcp config stat: %v", err),
				Timestamp: time.Now().UTC(),
			})
			continue
		}
		if info.IsDir() {
			continue
		}
		envs = append(envs, scanner.Environment{
			EnvType: EnvAIAgent,
			Name:    layoutMCPConfig,
			Path:    path,
		})
	}
	return envs, errs
}

// mcpConfigPaths returns every known MCP config location for the
// current OS + user.  Deliberately conservative: only well-known
// paths from the vendors' own docs, not a glob over ``~``.
func mcpConfigPaths() []string {
	home := userHome()
	if home == "" {
		return nil
	}
	var paths []string
	switch runtime.GOOS {
	case "darwin":
		paths = []string{
			filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"),
			filepath.Join(home, ".cursor", "mcp.json"),
			filepath.Join(home, ".claude", "mcp.json"),
			filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"),
		}
	case "linux":
		paths = []string{
			filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"),
			filepath.Join(home, ".cursor", "mcp.json"),
			filepath.Join(home, ".claude", "mcp.json"),
		}
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata != "" {
			paths = append(paths,
				filepath.Join(appdata, "Claude", "claude_desktop_config.json"),
			)
		}
		paths = append(paths,
			filepath.Join(home, ".cursor", "mcp.json"),
			filepath.Join(home, ".claude", "mcp.json"),
		)
	}
	return paths
}

// scanMCPConfig reads one mcp.json-shaped file and emits one
// PackageRecord per configured MCP server.  The record's ``Name``
// is the server key (``filesystem``, ``github``, ...); ``Version``
// is derived from the command/args when we can parse a version
// hint (``@modelcontextprotocol/server-filesystem@1.2.3`` → 1.2.3),
// otherwise left empty — many MCP configs don't pin a version.
//
// Read goes through ``safeio.ReadFile`` so the same
// symlink-refusal + size-bound policy every other parser uses
// applies here.  A symlinked mcp.json that points to
// /etc/shadow would otherwise exfiltrate host content into a
// scan record — not hypothetical; the agent has faced this
// exact class of attack via .deb copyright files.
func scanMCPConfig(path string) ([]scanner.PackageRecord, []scanner.ScanError) {
	data, err := safeio.ReadFile(path, maxMCPConfigBytes)
	if err != nil {
		// safeio surfaces ErrSymlink and ErrTooLarge as typed
		// sentinels; pass the message through verbatim so the
		// operator sees which policy triggered.
		return nil, []scanner.ScanError{{
			Path:      path,
			EnvType:   EnvAIAgent,
			Error:     fmt.Sprintf("mcp config read: %v", err),
			Timestamp: time.Now().UTC(),
		}}
	}
	// ``info`` is used below for the install-date proxy; fetch it
	// after the safeio read so the stat happens on the (verified,
	// non-symlink) file.  os.Stat here follows the link by design
	// — but at this point safeio has already confirmed the leaf
	// isn't a symlink, so there's no escape path left.
	info, err := os.Stat(path)
	if err != nil {
		return nil, []scanner.ScanError{{
			Path:      path,
			EnvType:   EnvAIAgent,
			Error:     fmt.Sprintf("mcp config stat: %v", err),
			Timestamp: time.Now().UTC(),
		}}
	}
	var cfg mcpConfigShape
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, []scanner.ScanError{{
			Path:      path,
			EnvType:   EnvAIAgent,
			Error:     fmt.Sprintf("mcp config parse: %v", err),
			Timestamp: time.Now().UTC(),
		}}
	}
	if len(cfg.MCPServers) == 0 {
		return nil, nil
	}
	// File mtime stands in for the install date — the last time
	// the user edited their MCP config is the closest proxy we
	// have to "when this server was first configured."  Good
	// enough for the install_age detective rule.
	installDate := info.ModTime().UTC()

	out := make([]scanner.PackageRecord, 0, len(cfg.MCPServers))
	for name, entry := range cfg.MCPServers {
		version := extractMCPVersion(entry)
		out = append(out, scanner.PackageRecord{
			Name:        "mcp:" + name,
			Version:     version,
			InstallPath: path,
			EnvType:     EnvAIAgent,
			Environment: path,
			InstallDate: installDate.Format(time.RFC3339),
		})
	}
	return out, nil
}

// extractMCPVersion pulls a version hint out of the command/args
// when one is present in a well-known shape.  Supports:
//
//   - ``npx -y @modelcontextprotocol/server-filesystem@1.2.3 …``
//   - ``docker run ghcr.io/github/github-mcp-server:1.4.0 …``
//   - ``uvx mcp-server-sqlite==0.2.1``
//
// Returns "" when nothing matches — we'd rather emit a versionless
// record than a made-up one.  CVE correlation gracefully treats
// empty-version as "any version" which is usually the right call
// for untagged MCP server configs.
func extractMCPVersion(entry mcpServerEntry) string {
	// Inspect each arg for a ``@<ver>`` suffix (npm/yarn style)
	// or ``==<ver>`` (pip/uv style) or ``:<ver>`` (docker).
	for _, arg := range entry.Args {
		if v := parseVersionSuffix(arg); v != "" {
			return v
		}
	}
	// docker run IMAGE:TAG — image may itself be an arg element.
	if entry.Command == "docker" {
		for _, arg := range entry.Args {
			if i := lastColon(arg); i >= 0 && isVersionish(arg[i+1:]) {
				return arg[i+1:]
			}
		}
	}
	return ""
}

// parseVersionSuffix tries ``pkg@1.2.3`` and ``pkg==1.2.3`` patterns.
// Returns the version portion if the suffix looks like a semver /
// PEP 440 version; otherwise "".
func parseVersionSuffix(s string) string {
	// ``==`` takes precedence because ``a==b`` also has an ``@`` if
	// the package name is ``@scope/pkg==1.2.3``.
	if i := indexOf(s, "=="); i >= 0 {
		v := s[i+2:]
		if isVersionish(v) {
			return v
		}
	}
	if i := lastIndex(s, "@"); i > 0 {
		// ``@scope/pkg@1.2.3`` — first ``@`` is the scope sigil,
		// last ``@`` is the version delimiter.  We use lastIndex
		// to skip the scope.
		v := s[i+1:]
		if isVersionish(v) {
			return v
		}
	}
	return ""
}

// isVersionish returns true if s looks like a version string
// (digit-leading, contains only digits / dots / dashes / letters).
// Deliberately loose — accepts ``1.2.3``, ``1.2.3-beta``, ``v1.0``.
// Rejects empty and non-digit-leading so ``@modelcontextprotocol``
// (the scope) doesn't pass.
func isVersionish(s string) bool {
	if s == "" {
		return false
	}
	first := s[0]
	// Allow leading 'v' as in ``v1.2.3``.
	if first == 'v' || first == 'V' {
		if len(s) < 2 {
			return false
		}
		first = s[1]
	}
	return first >= '0' && first <= '9'
}

// indexOf / lastIndex / lastColon — tiny helpers so we don't need
// to import strings just for this file's purposes.  Inlined here
// to keep the package's import surface small and auditable.
func indexOf(s, sub string) int {
	n := len(sub)
	for i := 0; i+n <= len(s); i++ {
		if s[i:i+n] == sub {
			return i
		}
	}
	return -1
}

func lastIndex(s, sub string) int {
	n := len(sub)
	for i := len(s) - n; i >= 0; i-- {
		if s[i:i+n] == sub {
			return i
		}
	}
	return -1
}

func lastColon(s string) int {
	return lastIndex(s, ":")
}
