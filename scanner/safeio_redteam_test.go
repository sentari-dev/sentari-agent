package scanner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRedTeam_PipMetadataSymlinkRefused models the attack we actually
// saw in the audit: a malicious site-packages entry ships its METADATA
// as a symlink to a sensitive file on the host.  Pre-safeio the scanner
// would ``os.ReadFile`` the symlink, follow it, and surface the target's
// contents in the license-raw field (which is uploaded to the server).
//
// With safeio in place, parseDistInfo must refuse to read the symlink
// and return an error — no part of the sensitive target reaches the
// PackageRecord.
func TestRedTeam_PipMetadataSymlinkRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires symlink creation privilege unavailable on default Windows")
	}
	tmp := t.TempDir()

	// Plant a "secret" file outside the scan root the scanner would
	// normally traverse.  The symlink points at it; any leak of its
	// contents means the defence failed.
	secret := filepath.Join(tmp, "secret.txt")
	const secretMarker = "DO-NOT-EXFILTRATE-PASSWORD-HASH"
	if err := os.WriteFile(secret, []byte(secretMarker), 0o600); err != nil {
		t.Fatal(err)
	}

	// Build a fake site-packages layout with METADATA as a symlink.
	sp := filepath.Join(tmp, "site-packages")
	distInfo := filepath.Join(sp, "victim-1.0.0.dist-info")
	if err := os.MkdirAll(distInfo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(distInfo, "METADATA")); err != nil {
		t.Skipf("symlink creation not permitted: %v", err)
	}

	// Run the scanner against tmp as root.
	cfg := Config{ScanRoot: tmp, MaxDepth: 6, MaxWorkers: 2}
	result, err := NewRunner(cfg).Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// No PackageRecord should exfiltrate the secret.  Any string
	// containing the marker in any field is a failure, full stop.
	for _, pkg := range result.Packages {
		for _, field := range []string{
			pkg.Name, pkg.Version, pkg.LicenseRaw,
			pkg.LicenseSPDX, pkg.InstallPath, pkg.InterpreterVersion,
		} {
			if strings.Contains(field, secretMarker) {
				t.Fatalf(
					"SECURITY REGRESSION: symlinked METADATA exfiltrated secret — package %+v",
					pkg,
				)
			}
		}
	}

	// The scanner is allowed to emit a ScanError about the refused
	// read, or silently skip.  We don't pin the exact path — we only
	// pin the absence of exfiltration above.
}

// TestRedTeam_CondaMetaSymlinkRefused: same attack class against a
// conda env.  conda-meta/*.json symlinked to /etc/shadow should not
// end up in the scan payload.
func TestRedTeam_CondaMetaSymlinkRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires symlink creation privilege unavailable on default Windows")
	}
	tmp := t.TempDir()

	secret := filepath.Join(tmp, "secret.txt")
	const secretMarker = "DO-NOT-EXFILTRATE-CONDA-SECRET"
	os.WriteFile(secret, []byte(secretMarker), 0o600)

	condaMeta := filepath.Join(tmp, "envs", "victim", "conda-meta")
	if err := os.MkdirAll(condaMeta, 0o755); err != nil {
		t.Fatal(err)
	}
	// JSON file that would normally be parsed — symlinked to the
	// secret to simulate a malicious env.
	if err := os.Symlink(secret, filepath.Join(condaMeta, "malicious-1.0.0.json")); err != nil {
		t.Skipf("symlink creation not permitted: %v", err)
	}

	cfg := Config{ScanRoot: tmp, MaxDepth: 8, MaxWorkers: 2}
	result, _ := NewRunner(cfg).Run(context.Background())

	for _, pkg := range result.Packages {
		for _, field := range []string{
			pkg.Name, pkg.Version, pkg.LicenseRaw, pkg.InstallPath,
		} {
			if strings.Contains(field, secretMarker) {
				t.Fatalf(
					"SECURITY REGRESSION: conda-meta symlink exfiltrated secret — %+v",
					pkg,
				)
			}
		}
	}
}

// TestRedTeam_PoetryLockSymlinkRefused: poetry.lock is a TOML file;
// the scanner reads the whole thing and regex-matches on [[package]]
// blocks.  A symlinked poetry.lock pointing at /etc/shadow would end
// up parsed as TOML garbage that sometimes happens to trip one of the
// regex arms.  safeio.ReadFile must refuse before any parse attempt.
func TestRedTeam_PoetryLockSymlinkRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink privilege")
	}
	tmp := t.TempDir()

	secret := filepath.Join(tmp, "secret.txt")
	const marker = "DO-NOT-EXFILTRATE-POETRY-SECRET"
	os.WriteFile(secret, []byte(marker), 0o600)

	proj := filepath.Join(tmp, "project")
	os.MkdirAll(proj, 0o755)
	if err := os.Symlink(secret, filepath.Join(proj, "poetry.lock")); err != nil {
		t.Skipf("symlink creation not permitted: %v", err)
	}

	cfg := Config{ScanRoot: tmp, MaxDepth: 6, MaxWorkers: 2}
	result, _ := NewRunner(cfg).Run(context.Background())

	for _, pkg := range result.Packages {
		for _, field := range []string{pkg.Name, pkg.Version, pkg.LicenseRaw} {
			if strings.Contains(field, marker) {
				t.Fatalf("SECURITY REGRESSION: poetry.lock symlink exfiltrated — %+v", pkg)
			}
		}
	}
	// Also assert no PackageRecord was produced at all for the
	// victim project — a refused read should not silently yield
	// a phantom package.
	for _, pkg := range result.Packages {
		if pkg.EnvType == EnvPoetry && strings.HasPrefix(pkg.InstallPath, proj) {
			t.Errorf("expected no poetry package from a refused lockfile, got %+v", pkg)
		}
	}
}

// TestRedTeam_OversizedMetadataRefused: a 10 MiB METADATA file must
// not be read.  Without the cap an attacker who controls a package's
// dist-info could ship a giant METADATA to exhaust agent memory.
func TestRedTeam_OversizedMetadataRefused(t *testing.T) {
	tmp := t.TempDir()
	sp := filepath.Join(tmp, "site-packages")
	di := filepath.Join(sp, "huge-1.0.0.dist-info")
	os.MkdirAll(di, 0o755)

	// 2 MiB is larger than maxPipMetadataSize (1 MiB) — bounded read
	// must reject.  Valid header at the top so a size-ignoring parser
	// would still extract a PackageRecord.
	body := []byte("Metadata-Version: 2.1\nName: huge\nVersion: 1.0.0\n\n")
	body = append(body, make([]byte, 2<<20)...)
	if err := os.WriteFile(filepath.Join(di, "METADATA"), body, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := Config{ScanRoot: tmp, MaxDepth: 6, MaxWorkers: 2}
	result, _ := NewRunner(cfg).Run(context.Background())

	for _, pkg := range result.Packages {
		if pkg.Name == "huge" {
			t.Errorf("oversized METADATA parsed; size-cap bypass — %+v", pkg)
		}
	}
}
