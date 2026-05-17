package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEnrichWithV3_findsLockfileInSampleProject is the H1 smoke test:
// create a tempdir with a minimal package-lock.json, run enrichWithV3
// scoped to that root, and assert at least one entry shows up in
// result.Lockfiles.  The full per-parser correctness is covered by
// the per-module unit tests under scanner/lockfiles and scanner/deptree;
// this test only verifies the wire-up.
func TestEnrichWithV3_findsLockfileInSampleProject(t *testing.T) {
	root := t.TempDir()
	// A lockfileVersion=3 package-lock.json with one package entry —
	// enough for both the lockfile-discovery side and the
	// ParseNpmPackageLock dispatch.
	lockJSON := `{
  "name": "smoke-test",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "smoke-test",
      "version": "1.0.0",
      "dependencies": {"left-pad": "1.3.0"}
    },
    "node_modules/left-pad": {
      "version": "1.3.0",
      "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"
    }
  }
}
`
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(lockJSON), 0o644); err != nil {
		t.Fatalf("write package-lock.json: %v", err)
	}

	result := &ScanResult{}
	enrichWithV3(result, []string{root})

	if len(result.Lockfiles) == 0 {
		t.Fatalf("expected at least one lockfile entry, got 0 (result=%+v)", result.Lockfiles)
	}
	// Sanity check on the entry shape: same path, npm ecosystem.
	found := false
	for _, lf := range result.Lockfiles {
		if filepath.Base(lf.Path) == "package-lock.json" && lf.Ecosystem == "npm" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected an npm package-lock.json entry, got %+v", result.Lockfiles)
	}
}
