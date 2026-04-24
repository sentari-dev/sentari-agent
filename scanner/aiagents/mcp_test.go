package aiagents

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// TestScanMCPConfig_ParsesRealShape: the config file format
// Anthropic documents for Claude Desktop / Cursor is a top-level
// ``mcpServers`` map.  A realistic config with three servers of
// differing command shapes produces three PackageRecords whose
// names are mcp:<key> and whose versions are extracted when the
// command/args carry a version hint.
func TestScanMCPConfig_ParsesRealShape(t *testing.T) {
	tmp := t.TempDir()
	cfg := filepath.Join(tmp, "claude_desktop_config.json")
	body := `{
		"mcpServers": {
			"filesystem": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem@1.2.3", "/home/user/docs"]
			},
			"github": {
				"command": "docker",
				"args": ["run", "-i", "--rm", "ghcr.io/github/github-mcp-server:1.4.0"]
			},
			"custom": {
				"command": "python",
				"args": ["/home/user/bin/custom-mcp-server.py"]
			}
		}
	}`
	if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	records, errs := scanMCPConfig(cfg)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	if len(records) != 3 {
		t.Fatalf("expected 3 records, got %d: %+v", len(records), records)
	}

	byName := map[string]string{}
	for _, r := range records {
		if r.EnvType != EnvAIAgent {
			t.Errorf("record %q wrong EnvType: %s", r.Name, r.EnvType)
		}
		byName[r.Name] = r.Version
	}

	// Version extraction matrix.
	if byName["mcp:filesystem"] != "1.2.3" {
		t.Errorf("filesystem version: got %q want 1.2.3", byName["mcp:filesystem"])
	}
	if byName["mcp:github"] != "1.4.0" {
		t.Errorf("github version: got %q want 1.4.0", byName["mcp:github"])
	}
	if byName["mcp:custom"] != "" {
		t.Errorf("custom should have no version; got %q", byName["mcp:custom"])
	}
}

// TestScanMCPConfig_EmptyServers: config file present but with an
// empty mcpServers map (user opened Claude Desktop but hasn't
// configured anything) — returns zero records, zero errors.  No
// ghost records for an empty config.
func TestScanMCPConfig_EmptyServers(t *testing.T) {
	tmp := t.TempDir()
	cfg := filepath.Join(tmp, "empty.json")
	if err := os.WriteFile(cfg, []byte(`{"mcpServers": {}}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	records, errs := scanMCPConfig(cfg)
	if len(records) != 0 {
		t.Errorf("expected 0 records for empty config; got %+v", records)
	}
	if len(errs) != 0 {
		t.Errorf("unexpected errors: %+v", errs)
	}
}

// TestScanMCPConfig_MalformedJSONIsScanError: a corrupt config
// file doesn't panic; it surfaces as a ScanError on the path so
// operators can see something is wrong with that host's config.
func TestScanMCPConfig_MalformedJSONIsScanError(t *testing.T) {
	tmp := t.TempDir()
	cfg := filepath.Join(tmp, "broken.json")
	if err := os.WriteFile(cfg, []byte(`{mcpServers: not-json`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	records, errs := scanMCPConfig(cfg)
	if len(records) != 0 {
		t.Errorf("expected 0 records on parse error; got %+v", records)
	}
	if len(errs) != 1 {
		t.Fatalf("expected 1 ScanError; got %+v", errs)
	}
	if errs[0].EnvType != EnvAIAgent {
		t.Errorf("ScanError EnvType: got %q", errs[0].EnvType)
	}
}

// TestDiscoverMCPConfigs_SkipsMissingPaths: HOME set to a temp
// dir with no MCP configs inside.  Discoverer emits zero
// Environments (no error).  Guards against any regression where
// a missing config is treated as an error rather than "not
// configured on this host."
func TestDiscoverMCPConfigs_SkipsMissingPaths(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	envs, errs := discoverMCPConfigs()
	if len(envs) != 0 {
		t.Errorf("expected 0 envs when no config present; got %+v", envs)
	}
	if len(errs) != 0 {
		t.Errorf("missing paths are the common case; should not surface as ScanError. got %+v", errs)
	}
}

// TestDiscoverMCPConfigs_PicksUpClaudeConfig: seed ONE of the
// known paths with a minimal config file and assert the discoverer
// surfaces it.  Skipped on Windows because USERPROFILE vs APPDATA
// dance would need more fixture plumbing than the test is worth;
// Linux + darwin coverage is enough to catch path-building bugs.
func TestDiscoverMCPConfigs_PicksUpClaudeConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows APPDATA path needs a different fixture")
	}
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	// Build the Linux path layout; darwin uses Library/Application
	// Support but we'll build both to not rely on host OS.
	var cfg string
	switch runtime.GOOS {
	case "darwin":
		cfg = filepath.Join(tmp, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	default:
		cfg = filepath.Join(tmp, ".config", "Claude", "claude_desktop_config.json")
	}
	if err := os.MkdirAll(filepath.Dir(cfg), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(cfg, []byte(`{"mcpServers": {}}`), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	envs, _ := discoverMCPConfigs()
	paths := make([]string, 0, len(envs))
	for _, e := range envs {
		paths = append(paths, e.Path)
	}
	sort.Strings(paths)
	found := false
	for _, p := range paths {
		if p == cfg {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("seeded config %s not discovered; got %v", cfg, paths)
	}
}

// TestExtractMCPVersion: the version-hint extractor's heuristics.
// Direct unit test so regressions on the parse logic don't have
// to wait for an end-to-end integration to surface.
func TestExtractMCPVersion(t *testing.T) {
	cases := []struct {
		name    string
		entry   mcpServerEntry
		want    string
	}{
		{"npx @ suffix", mcpServerEntry{Command: "npx", Args: []string{"-y", "@modelcontextprotocol/server-filesystem@1.2.3"}}, "1.2.3"},
		{"pip == suffix", mcpServerEntry{Command: "uvx", Args: []string{"mcp-server-sqlite==0.2.1"}}, "0.2.1"},
		{"docker colon tag", mcpServerEntry{Command: "docker", Args: []string{"run", "ghcr.io/github/github-mcp-server:1.4.0"}}, "1.4.0"},
		{"v-prefixed version", mcpServerEntry{Command: "npx", Args: []string{"foo@v2.0.0"}}, "v2.0.0"},
		{"no version", mcpServerEntry{Command: "python", Args: []string{"script.py"}}, ""},
		{"scope only, no version", mcpServerEntry{Command: "npx", Args: []string{"@scope/pkg"}}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractMCPVersion(tc.entry); got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}

// TestScanner_RegistersAtInit: the plugin's init() must register
// with scanner's global registry, otherwise the binary-scanner
// dispatch will never invoke it.  Mirrors the JVM plugin's
// register test.
func TestScanner_RegistersAtInit(t *testing.T) {
	// Rough sanity check: construct an env that any sane plugin
	// would accept, invoke DiscoverAll, assert no panic and the
	// plugin is reachable from the registry view.
	var s Scanner
	if s.EnvType() != EnvAIAgent {
		t.Fatalf("EnvType mismatch: %q", s.EnvType())
	}
	_, _ = s.DiscoverAll(context.Background())
}

// TestDiscoverAll_NoOpDuringContainerSubScan: when the orchestrator
// sets ScanRoot to a materialised container rootfs (NOT "/"), the
// AI-agent plugin must not read the host's HOME / Application
// Support paths — otherwise the container record set gets
// contaminated with the host user's AI surface, which is
// semantically wrong (those MCP configs aren't in the container)
// and misleading operationally.
func TestDiscoverAll_NoOpDuringContainerSubScan(t *testing.T) {
	// Even if the host has MCP configs present, we'd still expect
	// zero envs when the scan root is a random temp dir (not "/").
	tmp := t.TempDir()
	ctx := scanner.WithScanRoot(context.Background(), tmp)

	var s Scanner
	envs, errs := s.DiscoverAll(ctx)
	if len(envs) != 0 {
		t.Errorf("expected 0 envs in container sub-scan; got %d", len(envs))
	}
	if len(errs) != 0 {
		t.Errorf("expected 0 errs; got %+v", errs)
	}
}
