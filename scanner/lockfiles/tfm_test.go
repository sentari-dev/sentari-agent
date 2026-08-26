package lockfiles

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// Workspace Phase 5 §A — a project.assets.json's project.frameworks keys are
// extracted as short-form TFMs onto the LockfileMeta.
func TestDiscover_extractsTargetFrameworks(t *testing.T) {
	root := t.TempDir()
	assets := `{
      "version": 3,
      "targets": {".NETCoreApp,Version=v8.0": {"Newtonsoft.Json/13.0.3": {}}},
      "project": {"frameworks": {"net8.0": {}, "netstandard2.0": {}}}
    }`
	mustWrite(t, filepath.Join(root, "obj", "project.assets.json"), assets)

	results, err := DiscoverInRoot(context.Background(), root)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("want 1 lockfile, got %d", len(results))
	}
	got := results[0]
	if got.Format != "project_assets_json" || got.Ecosystem != "nuget" {
		t.Fatalf("wrong format/ecosystem: %+v", got)
	}
	// Sorted short-form TFMs from project.frameworks (NOT the long target keys).
	if strings.Join(got.TargetFrameworks, ",") != "net8.0,netstandard2.0" {
		t.Errorf("TargetFrameworks = %v, want [net8.0 netstandard2.0]", got.TargetFrameworks)
	}
}

// A non-.NET lockfile (or an assets file with no frameworks) carries no TFMs;
// the omitempty tag drops the field entirely.
func TestDiscover_noTargetFrameworksForNonDotnet(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "package-lock.json"), `{"lockfileVersion":3,"packages":{}}`)
	results, err := DiscoverInRoot(context.Background(), root)
	if err != nil {
		t.Fatalf("discover failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("want 1, got %d", len(results))
	}
	if results[0].TargetFrameworks != nil {
		t.Errorf("expected nil TargetFrameworks, got %v", results[0].TargetFrameworks)
	}
}

func TestTargetFrameworksFromAssets_malformed(t *testing.T) {
	if got := targetFrameworksFromAssets([]byte("not json")); got != nil {
		t.Errorf("want nil for malformed, got %v", got)
	}
	if got := targetFrameworksFromAssets([]byte(`{"project":{}}`)); got != nil {
		t.Errorf("want nil for no frameworks, got %v", got)
	}
}
