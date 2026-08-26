package runtimeversions

import (
	"context"
	"os"
	"path/filepath"
	"regexp"

	"github.com/sentari-dev/sentari-agent/scanner/pathfilter"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// Workspace Phase 5 §A — .NET runtime/SDK detection.
//
// Detection is directory ENUMERATION, never execution (constraint #7: the
// agent never invokes `dotnet --info`). A .NET install lays out its components
// under a fixed tree:
//
//	<root>/shared/Microsoft.NETCore.App/<version>/   → runtime
//	<root>/shared/Microsoft.AspNetCore.App/<version>/ → aspnetcore
//	<root>/sdk/<version>/                              → sdk (has a .version file)
//
// Each version-named directory becomes one InstalledRuntime whose Distro column
// carries the .NET *component* (runtime / aspnetcore / sdk) — mirroring the JDK
// detector's use of Distro for the vendor. The cycle is deterministic
// major.minor (CycleFor("dotnet", …)).

// _dotnetVersionMaxBytes caps the safeio read of an SDK's `.version` marker
// file — a short text file (a git sha + a version line); 4 KiB is generous.
const _dotnetVersionMaxBytes = 4 * 1024

// .NET version directories are semver-shaped: `8.0.8`, `8.0.303`, and preview
// builds like `9.0.0-preview.5.24306.7`. Anchor on major.minor.patch and allow
// an optional pre-release/build suffix; anything else (a stray `NuGetFallback`
// dir, etc.) is skipped.
var dotnetVersionDirRe = regexp.MustCompile(`^\d+\.\d+\.\d+`)

// .NET component sub-paths under a root and the Distro tag each maps to.
var dotnetSharedComponents = []struct {
	subdir string
	distro string
}{
	{filepath.Join("shared", "Microsoft.NETCore.App"), "runtime"},
	{filepath.Join("shared", "Microsoft.AspNetCore.App"), "aspnetcore"},
}

// DetectAllDotNet enumerates the .NET runtime/SDK installs under each candidate
// root. Pure directory inspection: one InstalledRuntime per version directory.
// Non-existent roots are silently skipped; symlinked entries are refused in
// step with the scanner's symlink-refusing posture.
func DetectAllDotNet(ctx context.Context, roots []string) []InstalledRuntime {
	var out []InstalledRuntime
	seen := map[string]bool{} // dedupe by absolute install path across overlapping roots
	for _, root := range roots {
		if ctx.Err() != nil {
			return out
		}
		root = filepath.Clean(root)
		if pathfilter.ShouldSkipDir(root) {
			continue
		}
		for _, comp := range dotnetSharedComponents {
			out = appendDotNetVersions(ctx, out, seen, filepath.Join(root, comp.subdir), comp.distro, false)
		}
		out = appendDotNetVersions(ctx, out, seen, filepath.Join(root, "sdk"), "sdk", true)
	}
	return out
}

// appendDotNetVersions enumerates the version directories directly under dir,
// emitting one InstalledRuntime per valid version. When requireSDKMarker is
// true (the SDK case) a version dir is only accepted if it holds a readable
// `.version` marker file — guarding against a stray non-SDK directory under
// sdk/.
func appendDotNetVersions(
	ctx context.Context,
	out []InstalledRuntime,
	seen map[string]bool,
	dir, distro string,
	requireSDKMarker bool,
) []InstalledRuntime {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if ctx.Err() != nil {
			return out
		}
		// Refuse symlinked version entries (a symlink DirEntry reports
		// IsDir()==false) so a symlink-farm can't redirect the reader.
		if !e.IsDir() {
			continue
		}
		version := e.Name()
		if !dotnetVersionDirRe.MatchString(version) {
			continue
		}
		installPath := filepath.Join(dir, version)
		if seen[installPath] {
			continue
		}
		if requireSDKMarker {
			markerPath := filepath.Join(installPath, ".version")
			// safeio refuses symlinks + oversize files and returns a real
			// error for a missing marker — either way, skip the candidate.
			if _, rerr := safeio.ReadFile(markerPath, _dotnetVersionMaxBytes); rerr != nil {
				continue
			}
		}
		seen[installPath] = true
		out = append(out, InstalledRuntime{
			Name:        RuntimeDotNet,
			Version:     version,
			Cycle:       CycleFor(RuntimeDotNet, version),
			Distro:      distro,
			InstallPath: installPath,
		})
	}
	return out
}
