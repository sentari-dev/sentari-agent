package gobinaries

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/pathfilter"
)

// copyFixtureInto copies the host fixture binary to dst (creating parent dirs).
func copyFixtureInto(t *testing.T, srcBin, dst string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(srcBin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

func distinctInstallPaths(recs []scanner.PackageRecord) map[string]struct{} {
	m := map[string]struct{}{}
	for _, r := range recs {
		m[r.InstallPath] = struct{}{}
	}
	return m
}

func TestScan_FindsBinariesInFixtureTree(t *testing.T) {
	src := hostFixtureBinary(t)
	root := t.TempDir()
	tool1 := filepath.Join(root, "tool1")
	tool2 := filepath.Join(root, "goos_arch", "tool2")
	tool3 := filepath.Join(root, "deep", "a", "b", "tool3")
	copyFixtureInto(t, src, tool1)
	copyFixtureInto(t, src, tool2)
	copyFixtureInto(t, src, tool3)
	// A script and a symlink that must both be ignored.
	if err := os.WriteFile(filepath.Join(root, "notgo.sh"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Symlink(tool1, filepath.Join(root, "link")); err != nil {
			t.Fatal(err)
		}
	}

	recs, errs := scanBinDir(context.Background(), root)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	paths := distinctInstallPaths(recs)
	if _, ok := paths[tool1]; !ok {
		t.Errorf("tool1 (depth 1) should be probed; paths=%v", paths)
	}
	if _, ok := paths[tool2]; !ok {
		t.Errorf("tool2 (depth 2) should be probed; paths=%v", paths)
	}
	if _, ok := paths[tool3]; ok {
		t.Errorf("tool3 (depth 3+) must NOT be probed (depth cap); paths=%v", paths)
	}
	if len(paths) != 2 {
		t.Errorf("want exactly 2 distinct binaries probed, got %d: %v", len(paths), paths)
	}
}

func TestScan_RespectsBinaryCountCap(t *testing.T) {
	orig := maxBinariesPerEnv
	maxBinariesPerEnv = 1
	defer func() { maxBinariesPerEnv = orig }()

	src := hostFixtureBinary(t)
	root := t.TempDir()
	copyFixtureInto(t, src, filepath.Join(root, "a_tool1"))
	copyFixtureInto(t, src, filepath.Join(root, "b_tool2"))

	recs, errs := scanBinDir(context.Background(), root)
	if got := len(distinctInstallPaths(recs)); got != 1 {
		t.Errorf("cap=1: want 1 binary probed, got %d", got)
	}
	if len(errs) != 1 {
		t.Fatalf("cap=1: want exactly one cap ScanError, got %d: %+v", len(errs), errs)
	}
}

func TestScan_CancelledContextStopsWalk(t *testing.T) {
	src := hostFixtureBinary(t)
	root := t.TempDir()
	copyFixtureInto(t, src, filepath.Join(root, "tool1"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	recs, errs := scanBinDir(ctx, root)
	if len(recs) != 0 {
		t.Errorf("cancelled scan should probe nothing, got %d records", len(recs))
	}
	if len(errs) == 0 {
		t.Fatal("cancelled scan must surface a ScanError")
	}
}

func TestScan_SkipDirHookHonoured(t *testing.T) {
	src := hostFixtureBinary(t)
	root := t.TempDir()
	copyFixtureInto(t, src, filepath.Join(root, "keep", "tool1"))
	skipped := filepath.Join(root, "skipme")
	copyFixtureInto(t, src, filepath.Join(skipped, "tool2"))

	restore := pathfilter.SetSkipDirHookForTest(func(p string) bool {
		return filepath.Base(p) == "skipme"
	})
	defer restore()

	recs, errs := scanBinDir(context.Background(), root)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	for p := range distinctInstallPaths(recs) {
		if filepath.Dir(p) == skipped {
			t.Errorf("binary under skipped dir must not be probed: %s", p)
		}
	}
	if len(distinctInstallPaths(recs)) != 1 {
		t.Errorf("want only the kept binary probed, got %v", distinctInstallPaths(recs))
	}
}

func TestScan_UnreadableEntryCollectsErrorAndContinues(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("chmod 0 directory semantics differ on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permission bits")
	}
	src := hostFixtureBinary(t)
	root := t.TempDir()
	copyFixtureInto(t, src, filepath.Join(root, "tool1"))
	locked := filepath.Join(root, "locked")
	copyFixtureInto(t, src, filepath.Join(locked, "tool2"))
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(locked, 0o755) //nolint:errcheck // best-effort cleanup

	recs, errs := scanBinDir(context.Background(), root)
	if _, ok := distinctInstallPaths(recs)[filepath.Join(root, "tool1")]; !ok {
		t.Error("sibling binary must still be probed after an unreadable subdir")
	}
	if len(errs) == 0 {
		t.Error("unreadable subdir should collect a ScanError")
	}
}
