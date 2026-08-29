//go:build darwin

package hardening

import (
	"context"
	"os"
)

// darwinPaths bundles the macOS source locations so the collector logic is
// exercised by unit tests (which point them at fixtures) rather than only on a
// real host.
type darwinPaths struct {
	fileVaultEvidence []string // presence => encrypted (never a false FAIL)
	alfPlist          string   // com.apple.alf (firewall)
	softwareUpdate    string   // com.apple.SoftwareUpdate (auto_update)
	screensaver       string   // com.apple.screensaver (screen_lock)
	// osMajor is the macOS major version; ALF's globalstate plist is stale on
	// macOS 15+ so firewall is emitted unknown there rather than a wrong value.
	osMajor int
}

// defaultDarwinPaths are the production locations + detected OS version.
func defaultDarwinPaths() darwinPaths {
	return darwinPaths{
		fileVaultEvidence: []string{
			"/var/db/FileVaultPRK.dat",
			"/System/Volumes/Preboot",
		},
		alfPlist:       "/Library/Preferences/com.apple.alf.plist",
		softwareUpdate: "/Library/Preferences/com.apple.SoftwareUpdate.plist",
		screensaver:    "/Library/Preferences/com.apple.screensaver.plist",
		osMajor:        darwinMajorVersion(),
	}
}

func collectPlatform(_ context.Context) []Observation {
	return darwinObservations(defaultDarwinPaths())
}

// darwinObservations builds the macOS hardening observation set.
func darwinObservations(p darwinPaths) []Observation {
	var obs []Observation
	obs = append(obs, guard(familyDiskEncryption, func() []Observation { return darwinFileVault(p.fileVaultEvidence) })...)
	obs = append(obs, guard(familyFirewall, func() []Observation { return darwinFirewall(p.alfPlist, p.osMajor) })...)
	obs = append(obs, guard(familyAutoUpdate, func() []Observation { return darwinAutoUpdate(p.softwareUpdate) })...)
	obs = append(obs, guard(familyScreenLock, func() []Observation { return darwinScreenLock(p.screensaver) })...)
	// kernel.* is not_applicable on macOS -> not emitted.
	return obs
}

// darwinFileVault emits disk_encryption.root_encrypted from enablement
// evidence: any evidence path present => true; none present => unknown (NEVER
// false — absence of the PRK file is not proof FileVault is off, so we refuse
// to emit a false FAIL, matching the contract's partial tier).
func darwinFileVault(evidence []string) []Observation {
	key := familyDiskEncryption + ".root_encrypted"
	for _, path := range evidence {
		if _, err := os.Stat(path); err == nil {
			return []Observation{obsValue(key, familyDiskEncryption, "true", path, "")}
		}
	}
	return []Observation{obsError(key, familyDiskEncryption, "", "no FileVault enablement evidence")}
}

// darwinFirewall emits firewall.enabled from com.apple.alf's globalstate. On
// macOS 15+ the ALF plist no longer reflects the live setting, so we emit
// unknown rather than a stale value.
func darwinFirewall(alfPath string, osMajor int) []Observation {
	key := familyFirewall + ".enabled"
	if osMajor >= 15 {
		return []Observation{obsError(key, familyFirewall, alfPath, "alf plist stale on macOS 15+")}
	}
	data, sha, reason := readSource(alfPath, maxPlistFileSize)
	if reason != "" {
		return []Observation{obsError(key, familyFirewall, alfPath, reason)}
	}
	val, ok := macFirewallEnabled(data)
	if !ok {
		return []Observation{obsError(key, familyFirewall, alfPath, "globalstate not readable")}
	}
	return []Observation{obsValue(key, familyFirewall, val, alfPath, sha)}
}

// darwinAutoUpdate emits auto_update.enabled from com.apple.SoftwareUpdate.
func darwinAutoUpdate(path string) []Observation {
	key := familyAutoUpdate + ".enabled"
	data, sha, reason := readSource(path, maxPlistFileSize)
	if reason != "" {
		return []Observation{obsError(key, familyAutoUpdate, path, reason)}
	}
	val, ok := macAutoUpdateEnabled(data)
	if !ok {
		return []Observation{obsError(key, familyAutoUpdate, path, "AutomaticCheckEnabled not readable")}
	}
	return []Observation{obsValue(key, familyAutoUpdate, val, path, sha)}
}

// darwinScreenLock emits screen_lock.enabled + screen_lock.timeout_secs from
// com.apple.screensaver (partial tier — system-level plist).
func darwinScreenLock(path string) []Observation {
	enabledKey := familyScreenLock + ".enabled"
	timeoutKey := familyScreenLock + ".timeout_secs"
	data, sha, reason := readSource(path, maxPlistFileSize)
	if reason != "" {
		return []Observation{
			obsError(enabledKey, familyScreenLock, path, reason),
			obsError(timeoutKey, familyScreenLock, path, reason),
		}
	}
	enabled, enOK, timeout, toOK := macScreenLock(data)
	var out []Observation
	if enOK {
		out = append(out, obsValue(enabledKey, familyScreenLock, enabled, path, sha))
	} else {
		out = append(out, obsError(enabledKey, familyScreenLock, path, "askForPassword not set"))
	}
	if toOK {
		out = append(out, obsValue(timeoutKey, familyScreenLock, timeout, path, sha))
	} else {
		out = append(out, obsError(timeoutKey, familyScreenLock, path, "askForPasswordDelay not set"))
	}
	return out
}
