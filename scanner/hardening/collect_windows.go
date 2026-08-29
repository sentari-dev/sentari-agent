//go:build windows

package hardening

import (
	"context"

	"golang.org/x/sys/windows/registry"
)

// collectPlatform runs the Windows hardening collectors. Registry-sourced
// observations carry a `registry:HKLM\...` pseudo-path and a null sha (there is
// no file to hash). Families that Windows cannot authoritatively answer in v1
// (account policy, audit, screen lock) are emitted unknown and ledgered
// server-side; kernel.* is not_applicable and not emitted.
func collectPlatform(_ context.Context) []Observation {
	var obs []Observation
	obs = append(obs, guard(familyFirewall, winFirewall)...)
	obs = append(obs, guard(familyAutoUpdate, winAutoUpdate)...)
	obs = append(obs, guard(familyTLS, winTLS)...)
	obs = append(obs, guard(familyDiskEncryption, winBitLocker)...)
	obs = append(obs, guard(familyAuthPolicy, winAuthPolicyUnknown)...)
	obs = append(obs, guard(familyAuditDaemon, winAuditUnknown)...)
	obs = append(obs, guard(familyScreenLock, winScreenLockUnknown)...)
	return obs
}

// regPath renders a stable registry pseudo-path for provenance.
func regPath(root, sub, value string) string {
	return "registry:" + root + `\` + sub + `\` + value
}

// readDword reads a REG_DWORD (or REG_QWORD) from HKLM\sub\value.
func readDword(sub, value string) (uint64, bool) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, sub, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(value)
	if err != nil {
		return 0, false
	}
	return v, true
}

// winFirewall reports firewall.enabled (full tier) from the three
// FirewallPolicy profiles. Enabled iff every readable profile has
// EnableFirewall=1.
func winFirewall() []Observation {
	key := familyFirewall + ".enabled"
	const base = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`
	profiles := []string{"DomainProfile", "StandardProfile", "PublicProfile"}
	anyRead := false
	allOn := true
	for _, p := range profiles {
		if v, ok := readDword(base+`\`+p, "EnableFirewall"); ok {
			anyRead = true
			if v == 0 {
				allOn = false
			}
		}
	}
	src := regPath("HKLM", base, "EnableFirewall")
	if !anyRead {
		return []Observation{obsError(key, familyFirewall, src, "FirewallPolicy not readable")}
	}
	return []Observation{obsValue(key, familyFirewall, boolStr(allOn), src, "")}
}

// winAutoUpdate reports auto_update.enabled (full tier) from WindowsUpdate\AU.
// NoAutoUpdate=0 (or AUOptions>=3) => enabled.
func winAutoUpdate() []Observation {
	key := familyAutoUpdate + ".enabled"
	const sub = `SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`
	if v, ok := readDword(sub, "NoAutoUpdate"); ok {
		return []Observation{obsValue(key, familyAutoUpdate, boolStr(v == 0), regPath("HKLM", sub, "NoAutoUpdate"), "")}
	}
	if v, ok := readDword(sub, "AUOptions"); ok {
		return []Observation{obsValue(key, familyAutoUpdate, boolStr(v >= 3), regPath("HKLM", sub, "AUOptions"), "")}
	}
	return []Observation{obsError(key, familyAutoUpdate, regPath("HKLM", sub, "NoAutoUpdate"), "WindowsUpdate\\AU policy not set")}
}

// winTLS reports tls.min_version (Schannel, config-derived partial). It walks
// the SCHANNEL Protocols keys and reports the lowest TLS version left enabled.
func winTLS() []Observation {
	minKey := familyTLS + ".min_version"
	const base = `SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols`
	versions := []string{"TLS 1.0", "TLS 1.1", "TLS 1.2", "TLS 1.3"}
	lowest := ""
	lowestAssumed := false // the chosen minimum came from an ABSENT key
	sawAny := false
	for _, ver := range versions {
		sub := base + `\` + ver + `\Server`
		v, ok := readDword(sub, "Enabled")
		if !ok {
			// Key absent: an absent Schannel protocol key means "OS default".
			// On Win11 22H2+/Server 2022+ TLS 1.0/1.1 default to DISABLED, so we
			// must NOT report an absent-key version as the enabled minimum as if
			// it were a configured fact. Record it, but flag it assumed.
			if lowest == "" {
				lowest = ver
				lowestAssumed = true
			}
			continue
		}
		sawAny = true
		if v != 0 && lowest == "" {
			lowest = ver
			lowestAssumed = false
		}
	}
	src := regPath("HKLM", base, "Enabled")
	if !sawAny {
		return []Observation{obsError(minKey, familyTLS, src, "Schannel protocol policy not configured")}
	}
	if lowestAssumed {
		// Minimum derives from an ABSENT key, not a read value. Emit it flagged
		// default_assumed=true (contract's Schannel default note) so an auditor
		// distinguishes an inherited OS default from a configured minimum.
		return []Observation{obsDefault(minKey, familyTLS, lowest, src, "")}
	}
	return []Observation{obsValue(minKey, familyTLS, lowest, src, "")}
}

// winAuthPolicyUnknown emits the six auth_policy keys as unknown: the Windows
// account policy lives in the locked SECURITY hive, which the agent cannot read
// without SYSTEM privileges and a hive-parse. Ledgered server-side.
func winAuthPolicyUnknown() []Observation {
	out := make([]Observation, 0, len(authPolicySlugs))
	for _, s := range authPolicySlugs {
		out = append(out, obsError(familyAuthPolicy+"."+s, familyAuthPolicy,
			`registry:HKLM\SECURITY\Policy`, "Windows account policy in locked SECURITY hive"))
	}
	return out
}

// winAuditUnknown emits audit_daemon.enabled as unknown (v1 Windows ledger).
func winAuditUnknown() []Observation {
	return []Observation{obsError(familyAuditDaemon+".enabled", familyAuditDaemon, "", "audit policy not assessed on Windows in v1")}
}

// winScreenLockUnknown emits the screen_lock keys as unknown (user-scoped ADMX,
// v1 Windows ledger).
func winScreenLockUnknown() []Observation {
	return []Observation{
		obsError(familyScreenLock+".enabled", familyScreenLock, "", "screen lock is user-scoped ADMX, not assessed on Windows in v1"),
		obsError(familyScreenLock+".timeout_secs", familyScreenLock, "", "screen lock is user-scoped ADMX, not assessed on Windows in v1"),
	}
}
