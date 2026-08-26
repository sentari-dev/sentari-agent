package runtimeversions

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// mkDotNetRuntime creates <root>/shared/<component>/<version>/ and returns root.
func mkComponentVersion(t *testing.T, root, component, version string) {
	t.Helper()
	dir := filepath.Join(root, "shared", component, version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

// mkSDK creates <root>/sdk/<version>/ with a .version marker.
func mkSDK(t *testing.T, root, version, marker string) {
	t.Helper()
	dir := filepath.Join(root, "sdk", version)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".version"), []byte(marker), 0o644); err != nil {
		t.Fatalf("write .version: %v", err)
	}
}

func componentKey(rt InstalledRuntime) string {
	return rt.Distro + ":" + rt.Version
}

func detectSorted(root string) []InstalledRuntime {
	got := DetectAllDotNet(context.Background(), []string{root})
	sort.Slice(got, func(i, j int) bool { return componentKey(got[i]) < componentKey(got[j]) })
	return got
}

func TestDetectDotNet_runtimeOnlyHost(t *testing.T) {
	root := t.TempDir()
	mkComponentVersion(t, root, "Microsoft.NETCore.App", "8.0.8")

	got := detectSorted(root)
	if len(got) != 1 {
		t.Fatalf("want 1 runtime, got %d: %+v", len(got), got)
	}
	rt := got[0]
	if rt.Name != "dotnet" || rt.Version != "8.0.8" || rt.Cycle != "8.0" || rt.Distro != "runtime" {
		t.Errorf("unexpected: %+v", rt)
	}
	if !strings.HasSuffix(rt.InstallPath, filepath.Join("Microsoft.NETCore.App", "8.0.8")) {
		t.Errorf("install path = %q", rt.InstallPath)
	}
}

func TestDetectDotNet_aspnetcoreComponent(t *testing.T) {
	root := t.TempDir()
	mkComponentVersion(t, root, "Microsoft.AspNetCore.App", "8.0.8")
	got := detectSorted(root)
	if len(got) != 1 || got[0].Distro != "aspnetcore" {
		t.Fatalf("want one aspnetcore, got %+v", got)
	}
}

func TestDetectDotNet_sdkHost(t *testing.T) {
	root := t.TempDir()
	mkSDK(t, root, "8.0.303", "abc123\n8.0.303\n")
	got := detectSorted(root)
	if len(got) != 1 || got[0].Distro != "sdk" || got[0].Version != "8.0.303" || got[0].Cycle != "8.0" {
		t.Fatalf("want one sdk 8.0.303, got %+v", got)
	}
}

func TestDetectDotNet_sideBySide(t *testing.T) {
	root := t.TempDir()
	mkComponentVersion(t, root, "Microsoft.NETCore.App", "6.0.33")
	mkComponentVersion(t, root, "Microsoft.NETCore.App", "8.0.8")
	mkComponentVersion(t, root, "Microsoft.AspNetCore.App", "8.0.8")
	mkSDK(t, root, "8.0.303", "sha\n8.0.303\n")

	got := detectSorted(root)
	keys := make([]string, 0, len(got))
	for _, rt := range got {
		keys = append(keys, componentKey(rt))
	}
	want := []string{"aspnetcore:8.0.8", "runtime:6.0.33", "runtime:8.0.8", "sdk:8.0.303"}
	if strings.Join(keys, ",") != strings.Join(want, ",") {
		t.Fatalf("keys = %v, want %v", keys, want)
	}
}

func TestDetectDotNet_sdkWithoutMarkerSkipped(t *testing.T) {
	root := t.TempDir()
	// A version-shaped dir under sdk/ with NO .version marker — not a real SDK.
	if err := os.MkdirAll(filepath.Join(root, "sdk", "8.0.303"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := DetectAllDotNet(context.Background(), []string{root}); len(got) != 0 {
		t.Fatalf("want 0 (no marker), got %+v", got)
	}
}

func TestDetectDotNet_nonVersionDirsSkipped(t *testing.T) {
	root := t.TempDir()
	// NuGetFallbackFolder + a stray file under the component dir must be ignored.
	if err := os.MkdirAll(filepath.Join(root, "sdk", "NuGetFallbackFolder"), 0o755); err != nil {
		t.Fatal(err)
	}
	mkComponentVersion(t, root, "Microsoft.NETCore.App", "not-a-version")
	if got := DetectAllDotNet(context.Background(), []string{root}); len(got) != 0 {
		t.Fatalf("want 0, got %+v", got)
	}
}

func TestDetectDotNet_oversizeVersionFileSkipped(t *testing.T) {
	root := t.TempDir()
	// A hostile oversized .version file (> _dotnetVersionMaxBytes) is refused by
	// safeio, so the SDK candidate is skipped rather than read unbounded.
	big := strings.Repeat("A", _dotnetVersionMaxBytes+1)
	mkSDK(t, root, "8.0.303", big)
	if got := DetectAllDotNet(context.Background(), []string{root}); len(got) != 0 {
		t.Fatalf("want 0 (oversize marker refused), got %+v", got)
	}
}

func TestDetectDotNet_symlinkedVersionDirSkipped(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir() // a real dir outside the tree
	compDir := filepath.Join(root, "shared", "Microsoft.NETCore.App")
	if err := os.MkdirAll(compDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(compDir, "9.0.0")); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if got := DetectAllDotNet(context.Background(), []string{root}); len(got) != 0 {
		t.Fatalf("want 0 (symlinked version dir skipped), got %+v", got)
	}
}

func TestDetectDotNet_missingRootSilent(t *testing.T) {
	got := DetectAllDotNet(context.Background(), []string{"/nonexistent/dotnet/root"})
	if len(got) != 0 {
		t.Fatalf("want 0 for missing root, got %+v", got)
	}
}

func TestDetectDotNet_dedupesOverlappingRoots(t *testing.T) {
	root := t.TempDir()
	mkComponentVersion(t, root, "Microsoft.NETCore.App", "8.0.8")
	// Same root twice → the install must be emitted once.
	got := DetectAllDotNet(context.Background(), []string{root, root})
	if len(got) != 1 {
		t.Fatalf("want 1 (deduped), got %d: %+v", len(got), got)
	}
}

func TestCycleFor_dotnet(t *testing.T) {
	cases := map[string]string{
		"8.0.8":                "8.0",
		"6.0.33":               "6.0",
		"9.0.0-preview.5.1234": "9.0",
		"10.0.1":               "10.0",
		"garbage":              "unknown",
	}
	for v, want := range cases {
		if got := CycleFor("dotnet", v); got != want {
			t.Errorf("CycleFor(dotnet, %q) = %q, want %q", v, got, want)
		}
	}
}

func TestLanguageRuntimeNames_includesDotNet(t *testing.T) {
	found := false
	for _, n := range LanguageRuntimeNames() {
		if n == "dotnet" {
			found = true
		}
	}
	if !found {
		t.Error("LanguageRuntimeNames() must include dotnet (drift-guard forces the schema enum)")
	}
}
