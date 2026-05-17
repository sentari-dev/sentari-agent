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

// TestEnrichWithV3_dispatchesNuGetPackagesLock confirms the fix for
// the previously-empty `case "packages_lock_json"` branch: a project
// that ships packages.lock.json without a sibling
// obj/project.assets.json must still produce dep_edges via the
// lock-only parser.
func TestEnrichWithV3_dispatchesNuGetPackagesLock(t *testing.T) {
	root := t.TempDir()
	lockJSON := `{
  "version": 1,
  "dependencies": {
    "net6.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "test"
      }
    }
  }
}
`
	if err := os.WriteFile(filepath.Join(root, "packages.lock.json"), []byte(lockJSON), 0o644); err != nil {
		t.Fatalf("write packages.lock.json: %v", err)
	}

	result := &ScanResult{}
	enrichWithV3(result, []string{root})

	if len(result.DepEdges) == 0 {
		t.Fatalf("expected dep edges from packages.lock.json fallback, got 0 (lockfiles=%+v)", result.Lockfiles)
	}
}

// TestEnrichWithV3_skipsHomeCacheWalksWhenEcosystemNotDiscovered
// confirms the fix that gates ~/.m2/repository and ~/.nuget/packages
// walks behind a discovered project of that ecosystem.  Strategy:
// run enrichWithV3 against a tempdir containing only a pypi lockfile
// and assert no Maven/NuGet supply-chain signals or license rows ever
// appear, regardless of what's in the operator's actual home dir.
func TestEnrichWithV3_skipsHomeCacheWalksWhenEcosystemNotDiscovered(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("requests==2.31.0\n"), 0o644); err != nil {
		t.Fatalf("write requirements.txt: %v", err)
	}

	result := &ScanResult{}
	enrichWithV3(result, []string{root})

	for _, s := range result.SupplyChainSignals {
		if s.Ecosystem == "maven" || s.Ecosystem == "nuget" {
			t.Errorf("unexpected %s supply-chain signal from scoped pypi-only scan: %+v", s.Ecosystem, s)
		}
	}
	for _, lic := range result.LicenseEvidence {
		if lic.Ecosystem == "maven" || lic.Ecosystem == "nuget" {
			t.Errorf("unexpected %s license evidence from scoped pypi-only scan: %+v", lic.Ecosystem, lic)
		}
	}
}
