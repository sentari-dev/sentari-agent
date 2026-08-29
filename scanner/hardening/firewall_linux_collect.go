package hardening

import (
	"os"
	"path/filepath"
	"strings"
)

// collectFirewallLinux reports firewall.enabled from configuration evidence
// (partial tier — NOT the live kernel ruleset, which would require nft/iptables
// invocation, forbidden by constraint #7). Precedence:
//
//  1. ufw: /etc/ufw/ufw.conf `ENABLED=yes`.
//  2. firewalld: presence of its config dir + a default zone.
//  3. nftables: a non-empty ruleset in /etc/nftables.conf.
//
// The first source that exists decides; if none exists the value is unknown
// (we cannot see the live ruleset).
func collectFirewallLinux(ufwConf, firewalldDir, nftablesConf string) []Observation {
	key := familyFirewall + ".enabled"

	// ufw.
	if data, sha, reason := readSource(ufwConf, maxConfigFileSize); reason == "" {
		kv := parseEqualsKV(data)
		enabled := strings.EqualFold(kv["enabled"], "yes") || strings.EqualFold(kv["enabled"], "true")
		return []Observation{obsValue(key, familyFirewall, boolStr(enabled), ufwConf, sha)}
	}

	// firewalld: the config directory exists whenever firewalld is merely
	// INSTALLED, enabled or not — its bare presence is NOT enablement evidence
	// (that was a false PASS). Require firewalld.conf with a DefaultZone as
	// configuration evidence of an active policy (partial tier — still not the
	// live daemon state, which would need firewall-cmd, constraint #7).
	if fi, err := os.Stat(firewalldDir); err == nil && fi.IsDir() {
		confPath := filepath.Join(firewalldDir, "firewalld.conf")
		if data, sha, reason := readSource(confPath, maxConfigFileSize); reason == "" {
			if firewalldHasDefaultZone(data) {
				return []Observation{obsValue(key, familyFirewall, "true", confPath, sha)}
			}
			return []Observation{obsError(key, familyFirewall, confPath, "firewalld.conf has no DefaultZone")}
		}
		return []Observation{obsError(key, familyFirewall, firewalldDir, "firewalld installed but enablement not readable")}
	}

	// nftables: a ruleset file with at least one `table`/`chain` line.
	if data, sha, reason := readSource(nftablesConf, maxConfigFileSize); reason == "" {
		return []Observation{obsValue(key, familyFirewall, boolStr(nftablesHasRules(data)), nftablesConf, sha)}
	}

	return []Observation{obsError(key, familyFirewall, ufwConf, "no firewall config found")}
}

// firewalldHasDefaultZone reports whether firewalld.conf sets a non-empty
// DefaultZone — evidence firewalld is configured with an active zone policy.
func firewalldHasDefaultZone(data []byte) bool {
	return strings.TrimSpace(parseEqualsKV(data)["defaultzone"]) != ""
}

// nftablesHasRules reports whether an nftables config declares any table.
func nftablesHasRules(data []byte) bool {
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "table ") {
			return true
		}
	}
	return false
}

// boolStr renders a Go bool as the canonical "true"/"false" observation value.
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
