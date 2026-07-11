package aiagents

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// TestScannerScanDispatch covers Scanner.Scan — the production dispatch
// entrypoint that routes a discovered Environment to the correct per-surface
// walker by its Name (layout tag). Each layout gets a minimal on-disk fixture,
// and routing is asserted via the record-name prefix that only the intended
// walker produces (mcp: / agent: / ide-ext:).
func TestScannerScanDispatch(t *testing.T) {
	cases := []struct {
		name       string
		layout     string
		path       func(t *testing.T) string
		wantPrefix string
	}{
		{
			name:   "mcp-config routes to scanMCPConfig",
			layout: layoutMCPConfig,
			path: func(t *testing.T) string {
				cfg := filepath.Join(t.TempDir(), "mcp.json")
				body := `{"mcpServers":{"github":{"command":"github-mcp-server"}}}`
				if err := os.WriteFile(cfg, []byte(body), 0o644); err != nil {
					t.Fatalf("write mcp config: %v", err)
				}
				return cfg
			},
			wantPrefix: "mcp:",
		},
		{
			name:   "claude-code routes to scanClaudeCode",
			layout: layoutClaudeCode,
			path: func(t *testing.T) string {
				// scanClaudeCode dispatches on filepath.Base(path); "agents"
				// is the files-only subdir producing "agent:<name>" records.
				agents := filepath.Join(t.TempDir(), "agents")
				if err := os.MkdirAll(agents, 0o755); err != nil {
					t.Fatalf("mkdir agents: %v", err)
				}
				if err := os.WriteFile(filepath.Join(agents, "reviewer.md"), []byte("---\n"), 0o644); err != nil {
					t.Fatalf("write agent: %v", err)
				}
				return agents
			},
			wantPrefix: "agent:",
		},
		{
			name:   "ide-extensions routes to scanIDEExtensions",
			layout: layoutIDEExtensions,
			path: func(t *testing.T) string {
				root := t.TempDir()
				ext := filepath.Join(root, "github.copilot-1.0.0")
				if err := os.MkdirAll(ext, 0o755); err != nil {
					t.Fatalf("mkdir ext: %v", err)
				}
				// publisher.name must be in the known-AI allowlist to emit.
				manifest := `{"publisher":"github","name":"copilot","version":"1.0.0"}`
				if err := os.WriteFile(filepath.Join(ext, "package.json"), []byte(manifest), 0o644); err != nil {
					t.Fatalf("write manifest: %v", err)
				}
				return root
			},
			wantPrefix: "ide-ext:",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := scanner.Environment{
				EnvType: EnvAIAgent,
				Name:    tc.layout,
				Path:    tc.path(t),
			}
			recs, errs := Scanner{}.Scan(context.Background(), env)
			if len(errs) != 0 {
				t.Fatalf("unexpected scan errors: %+v", errs)
			}
			if len(recs) == 0 {
				t.Fatalf("layout %q produced no records; walker not reached", tc.layout)
			}
			for _, r := range recs {
				if !strings.HasPrefix(r.Name, tc.wantPrefix) {
					t.Errorf("record %q lacks prefix %q — wrong walker for layout %q", r.Name, tc.wantPrefix, tc.layout)
				}
			}
		})
	}
}

// TestScannerScanUnknownLayout verifies the loud-on-dispatch-bug default arm:
// an Environment whose Name is not a known layout tag yields exactly one
// ScanError describing the unknown layout and no records — surfacing a
// discovery/scan wiring mismatch instead of silently dropping it.
func TestScannerScanUnknownLayout(t *testing.T) {
	env := scanner.Environment{
		EnvType: EnvAIAgent,
		Name:    "bogus-layout",
		Path:    "/some/path",
	}
	recs, errs := Scanner{}.Scan(context.Background(), env)
	if len(recs) != 0 {
		t.Fatalf("expected no records for unknown layout, got %+v", recs)
	}
	if len(errs) != 1 {
		t.Fatalf("expected exactly 1 ScanError, got %d: %+v", len(errs), errs)
	}
	if errs[0].EnvType != EnvAIAgent {
		t.Errorf("ScanError EnvType = %q, want %q", errs[0].EnvType, EnvAIAgent)
	}
	if errs[0].Path != env.Path {
		t.Errorf("ScanError Path = %q, want %q", errs[0].Path, env.Path)
	}
	if want := `unknown ai_agent layout: "bogus-layout"`; errs[0].Error != want {
		t.Errorf("ScanError Error = %q, want %q", errs[0].Error, want)
	}
	if errs[0].Timestamp.IsZero() {
		t.Errorf("ScanError Timestamp is zero, want a set UTC time")
	}
}
