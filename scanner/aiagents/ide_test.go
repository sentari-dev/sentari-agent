package aiagents

import (
	"os"
	"path/filepath"
	"testing"
)

// writeExt is a tiny helper that drops a VS Code extension dir
// with a minimal package.json manifest into root.
func writeExt(t *testing.T, root, publisher, name, version string) {
	t.Helper()
	dir := filepath.Join(root, publisher+"."+name+"-"+version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	manifest := `{
		"publisher": "` + publisher + `",
		"name": "` + name + `",
		"version": "` + version + `",
		"displayName": "` + name + ` display"
	}`
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
}

// TestScanIDEExtensions_FiltersByAllowlist: only extensions whose
// publisher.name is in the known-AI allowlist are emitted.  A
// GitHub Copilot install surfaces; a random lint-only extension
// does not (this scanner is not a generic VS Code extension
// inventory — that's a separate concern).
func TestScanIDEExtensions_FiltersByAllowlist(t *testing.T) {
	tmp := t.TempDir()
	writeExt(t, tmp, "github", "copilot", "1.200.0")          // AI — keep
	writeExt(t, tmp, "github", "copilot-chat", "0.12.0")      // AI — keep
	writeExt(t, tmp, "continue", "continue", "0.8.54")        // AI — keep
	writeExt(t, tmp, "esbenp", "prettier-vscode", "10.4.0")   // not AI — drop
	writeExt(t, tmp, "dbaeumer", "vscode-eslint", "3.0.10")   // not AI — drop

	records, errs := scanIDEExtensions(tmp)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	names := map[string]bool{}
	for _, r := range records {
		names[r.Name] = true
	}
	wantAI := []string{"ide-ext:github.copilot", "ide-ext:github.copilot-chat", "ide-ext:continue.continue"}
	wantNotAI := []string{"ide-ext:esbenp.prettier-vscode", "ide-ext:dbaeumer.vscode-eslint"}
	for _, n := range wantAI {
		if !names[n] {
			t.Errorf("expected AI extension %s to be emitted; got %v", n, names)
		}
	}
	for _, n := range wantNotAI {
		if names[n] {
			t.Errorf("non-AI extension %s leaked through filter", n)
		}
	}
}

// TestScanIDEExtensions_VersionFromManifest: the emitted record's
// Version is the manifest's version field.  Confirms we don't
// accidentally pull from the directory name or leave it empty.
func TestScanIDEExtensions_VersionFromManifest(t *testing.T) {
	tmp := t.TempDir()
	writeExt(t, tmp, "github", "copilot", "1.200.0")
	records, _ := scanIDEExtensions(tmp)
	if len(records) != 1 {
		t.Fatalf("expected 1 record; got %+v", records)
	}
	if records[0].Version != "1.200.0" {
		t.Errorf("version: got %q want 1.200.0", records[0].Version)
	}
}

// TestScanIDEExtensions_MalformedManifestSkipped: a directory with
// an invalid package.json produces a ScanError but doesn't block
// the walk.  Other valid extensions still surface.
func TestScanIDEExtensions_MalformedManifestSkipped(t *testing.T) {
	tmp := t.TempDir()
	// Broken manifest.
	broken := filepath.Join(tmp, "github.copilot-broken")
	if err := os.MkdirAll(broken, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(broken, "package.json"), []byte("{not-json"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Valid one nearby.
	writeExt(t, tmp, "continue", "continue", "0.8.0")

	records, errs := scanIDEExtensions(tmp)
	// Expect the valid one to be present.
	if len(records) < 1 {
		t.Errorf("valid extension not surfaced alongside broken one: %+v", records)
	}
	// Expect at least one ScanError naming the broken manifest.
	found := false
	for _, e := range errs {
		if e.EnvType == EnvAIAgent && e.Error != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a ScanError for broken manifest; got none")
	}
}

// TestDiscoverIDEExtensions_SkipsMissing: no extensions dirs
// present under HOME → 0 envs (not an error).
func TestDiscoverIDEExtensions_SkipsMissing(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	envs := discoverIDEExtensions()
	if len(envs) != 0 {
		t.Errorf("expected 0 envs; got %+v", envs)
	}
}
