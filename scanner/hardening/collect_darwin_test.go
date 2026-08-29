//go:build darwin

package hardening

import (
	"context"
	"path/filepath"
	"testing"
)

// macPlist writes a minimal XML plist file and returns its path.
func macPlist(t *testing.T, dir, name, body string) string {
	t.Helper()
	return writeTemp(t, dir, name, `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>`+body+`</dict></plist>`)
}

// TestDarwinObservations wires the darwin dispatcher against fixture paths and
// asserts each family's value + honesty semantics (unknown where evidence is
// absent, never a false FAIL).
func TestDarwinObservations(t *testing.T) {
	dir := t.TempDir()
	p := darwinPaths{
		fileVaultEvidence: []string{macPlist(t, dir, "FileVaultPRK.dat", "")}, // present => true
		alfPlist:          macPlist(t, dir, "alf.plist", `<key>globalstate</key><integer>1</integer>`),
		softwareUpdate:    macPlist(t, dir, "su.plist", `<key>AutomaticCheckEnabled</key><true/>`),
		screensaver:       macPlist(t, dir, "ss.plist", `<key>askForPassword</key><integer>1</integer><key>askForPasswordDelay</key><integer>60</integer>`),
		osMajor:           14,
	}
	obs := darwinObservations(p)
	assertValue(t, mustObs(t, obs, "disk_encryption.root_encrypted"), "true")
	assertValue(t, mustObs(t, obs, "firewall.enabled"), "true")
	assertValue(t, mustObs(t, obs, "auto_update.enabled"), "true")
	assertValue(t, mustObs(t, obs, "screen_lock.enabled"), "true")
	assertValue(t, mustObs(t, obs, "screen_lock.timeout_secs"), "60")
	// kernel.* is not_applicable on macOS => not emitted.
	if findObs(obs, "kernel.randomize_va_space") != nil {
		t.Error("kernel family must not be emitted on darwin")
	}
}

// TestDarwinFileVault_NoEvidenceIsUnknown: absence of the PRK file is not proof
// FileVault is off, so we emit unknown, NEVER a false "false".
func TestDarwinFileVault_NoEvidenceIsUnknown(t *testing.T) {
	obs := darwinFileVault([]string{filepath.Join(t.TempDir(), "absent")})
	assertUnknown(t, obs[0], "no FileVault enablement evidence")
}

// TestDarwinFirewall_StaleOnMacOS15: on macOS 15+ the ALF plist no longer
// reflects the live setting, so firewall is emitted unknown rather than a
// wrong value.
func TestDarwinFirewall_StaleOnMacOS15(t *testing.T) {
	dir := t.TempDir()
	alf := macPlist(t, dir, "alf.plist", `<key>globalstate</key><integer>1</integer>`)
	obs := darwinFirewall(alf, 15)
	assertUnknown(t, obs[0], "alf plist stale on macOS 15+")

	// <15 reads the plist authoritatively.
	obs = darwinFirewall(alf, 14)
	assertValue(t, obs[0], "true")

	// Unreadable plist => unknown (classified reason).
	obs = darwinFirewall(filepath.Join(dir, "absent.plist"), 14)
	assertUnknown(t, obs[0], "not found")

	// Readable but globalstate missing => unknown.
	bad := macPlist(t, dir, "bad.plist", `<key>other</key><integer>1</integer>`)
	obs = darwinFirewall(bad, 14)
	assertUnknown(t, obs[0], "globalstate not readable")
}

func TestDarwinAutoUpdate(t *testing.T) {
	dir := t.TempDir()
	su := macPlist(t, dir, "su.plist", `<key>AutomaticCheckEnabled</key><false/>`)
	assertValue(t, darwinAutoUpdate(su)[0], "false")

	assertUnknown(t, darwinAutoUpdate(filepath.Join(dir, "absent"))[0], "not found")

	bad := macPlist(t, dir, "bad.plist", `<key>other</key><true/>`)
	assertUnknown(t, darwinAutoUpdate(bad)[0], "AutomaticCheckEnabled not readable")
}

func TestDarwinScreenLock(t *testing.T) {
	dir := t.TempDir()
	full := macPlist(t, dir, "ss.plist", `<key>askForPassword</key><integer>1</integer><key>askForPasswordDelay</key><integer>5</integer>`)
	obs := darwinScreenLock(full)
	assertValue(t, mustObs(t, obs, "screen_lock.enabled"), "true")
	assertValue(t, mustObs(t, obs, "screen_lock.timeout_secs"), "5")

	// Unreadable => both keys unknown.
	obs = darwinScreenLock(filepath.Join(dir, "absent"))
	assertUnknown(t, mustObs(t, obs, "screen_lock.enabled"), "not found")
	assertUnknown(t, mustObs(t, obs, "screen_lock.timeout_secs"), "not found")

	// Keys absent => per-key unknown reasons.
	empty := macPlist(t, dir, "empty.plist", `<key>moduleName</key><string>Flurry</string>`)
	obs = darwinScreenLock(empty)
	assertUnknown(t, mustObs(t, obs, "screen_lock.enabled"), "askForPassword not set")
	assertUnknown(t, mustObs(t, obs, "screen_lock.timeout_secs"), "askForPasswordDelay not set")
}

// TestDarwinMajorVersion repoints systemVersionPath at a fixture SystemVersion
// plist and asserts the major component is parsed (never invoking sw_vers).
func TestDarwinMajorVersion(t *testing.T) {
	dir := t.TempDir()
	orig := systemVersionPath
	t.Cleanup(func() { systemVersionPath = orig })

	systemVersionPath = macPlist(t, dir, "SystemVersion.plist", `<key>ProductVersion</key><string>14.5</string>`)
	if got := darwinMajorVersion(); got != 14 {
		t.Errorf("darwinMajorVersion=%d, want 14", got)
	}

	// Missing file => 0 (unknown).
	systemVersionPath = filepath.Join(dir, "absent.plist")
	if got := darwinMajorVersion(); got != 0 {
		t.Errorf("missing SystemVersion => %d, want 0", got)
	}

	// Malformed version string => 0.
	systemVersionPath = macPlist(t, dir, "bad.plist", `<key>ProductVersion</key><string>notaversion</string>`)
	if got := darwinMajorVersion(); got != 0 {
		t.Errorf("bad version => %d, want 0", got)
	}
}

// TestCollectPlatform_Darwin exercises the real dispatcher (production paths).
// It must not panic and returns a set within the cap; values depend on the host
// so we only assert structural invariants.
func TestCollectPlatform_Darwin(t *testing.T) {
	obs := collectPlatform(context.Background())
	if len(obs) == 0 {
		t.Fatal("darwin collectPlatform returned no observations")
	}
	for _, o := range obs {
		if o.Key == "" || o.Family == "" {
			t.Errorf("observation missing key/family: %+v", o)
		}
	}
}
