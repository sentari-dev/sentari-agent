package hardening

import (
	"os"
	"strings"
)

// collectAuditDaemon reports audit_daemon.enabled (Linux auditd, full tier).
// Evidence: the auditd config file exists AND at least one rules file is
// present (a configured audit subsystem). We read config, never invoke
// auditctl/systemctl (constraint #7). rulesFile is /etc/audit/audit.rules;
// rulesDir is /etc/audit/rules.d.
func collectAuditDaemon(auditdConf, rulesFile, rulesDir string) []Observation {
	key := familyAuditDaemon + ".enabled"

	_, sha, reason := readSource(auditdConf, maxConfigFileSize)
	if reason != "" {
		if reason == "not found" {
			// Genuinely absent auditd.conf -> auditd not installed/configured.
			return []Observation{obsValue(key, familyAuditDaemon, "false", auditdConf, "")}
		}
		// Permission-denied / unreadable is NOT proof the daemon is off — a
		// locked-down but compliant host must not read as failing. Emit unknown.
		return []Observation{obsError(key, familyAuditDaemon, auditdConf, reason)}
	}
	if auditHasRules(rulesFile, rulesDir) {
		return []Observation{obsValue(key, familyAuditDaemon, "true", auditdConf, sha)}
	}
	// Config present but no rules loaded — the daemon may run but is not
	// enforcing any rules; report false with the config as provenance.
	return []Observation{obsValue(key, familyAuditDaemon, "false", auditdConf, sha)}
}

// auditHasRules reports whether any non-empty *.rules file exists.
func auditHasRules(rulesFile, rulesDir string) bool {
	if fi, err := os.Stat(rulesFile); err == nil && fi.Size() > 0 {
		return true
	}
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rules") {
			continue
		}
		if fi, err := e.Info(); err == nil && fi.Size() > 0 {
			return true
		}
	}
	return false
}

// collectAutoUpdateLinux reports auto_update.enabled (full tier). apt:
// /etc/apt/apt.conf.d/20auto-upgrades `APT::Periodic::Unattended-Upgrade "1"`.
// dnf: /etc/dnf/automatic.conf `apply_updates = yes`.
func collectAutoUpdateLinux(aptAutoUpgrades, dnfAutomatic string) []Observation {
	key := familyAutoUpdate + ".enabled"

	if data, sha, reason := readSource(aptAutoUpgrades, maxConfigFileSize); reason == "" {
		return []Observation{obsValue(key, familyAutoUpdate, boolStr(aptUnattendedEnabled(data)), aptAutoUpgrades, sha)}
	}
	if data, sha, reason := readSource(dnfAutomatic, maxConfigFileSize); reason == "" {
		kv := parseEqualsKV(data)
		return []Observation{obsValue(key, familyAutoUpdate, boolStr(strings.EqualFold(kv["apply_updates"], "yes")), dnfAutomatic, sha)}
	}
	return []Observation{obsError(key, familyAutoUpdate, aptAutoUpgrades, "no auto-update config found")}
}

// aptUnattendedEnabled parses the APT::Periodic block for
// Unattended-Upgrade "1".
func aptUnattendedEnabled(data []byte) bool {
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "//") || line == "" {
			continue
		}
		if strings.Contains(line, "Unattended-Upgrade") && strings.Contains(line, `"1"`) {
			return true
		}
	}
	return false
}

// collectScreenLockLinux reports screen_lock.* from the system dconf database
// (partial tier — system-level only, a user session can override). It reads
// the plain-text dconf keyfiles under dconfDir (e.g.
// /etc/dconf/db/local.d) for the org/gnome/desktop/screensaver group.
func collectScreenLockLinux(dconfDir string) []Observation {
	enabledKey := familyScreenLock + ".enabled"
	timeoutKey := familyScreenLock + ".timeout_secs"

	group, srcPath, sha, found := dconfScreensaverGroup(dconfDir)
	if !found {
		return []Observation{
			obsError(enabledKey, familyScreenLock, dconfDir, "no system dconf screensaver policy"),
			obsError(timeoutKey, familyScreenLock, dconfDir, "no system dconf screensaver policy"),
		}
	}
	var out []Observation
	if v, ok := group["lock-enabled"]; ok {
		out = append(out, obsValue(enabledKey, familyScreenLock, normalizeDconfBool(v), srcPath, sha))
	} else {
		out = append(out, obsError(enabledKey, familyScreenLock, srcPath, "lock-enabled not set"))
	}
	if v, ok := group["lock-delay"]; ok {
		out = append(out, obsValue(timeoutKey, familyScreenLock, stripDconfType(v), srcPath, sha))
	} else if v, ok := group["idle-delay"]; ok {
		out = append(out, obsValue(timeoutKey, familyScreenLock, stripDconfType(v), srcPath, sha))
	} else {
		out = append(out, obsError(timeoutKey, familyScreenLock, srcPath, "lock-delay not set"))
	}
	return out
}

// dconfScreensaverGroup finds the [org/gnome/desktop/screensaver] group in the
// first readable keyfile under dconfDir and returns its key/value map.
func dconfScreensaverGroup(dconfDir string) (map[string]string, string, string, bool) {
	entries, err := os.ReadDir(dconfDir)
	if err != nil {
		return nil, "", "", false
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := dconfDir + "/" + e.Name()
		data, sha, reason := readSource(path, maxConfigFileSize)
		if reason != "" {
			continue
		}
		if g, ok := parseINISection(data, "org/gnome/desktop/screensaver"); ok {
			return g, path, sha, true
		}
	}
	return nil, "", "", false
}

// parseINISection returns the key/value map of one [section] from an INI-style
// keyfile.
func parseINISection(data []byte, section string) (map[string]string, bool) {
	m := map[string]string{}
	cur := ""
	found := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			cur = strings.TrimSpace(line[1 : len(line)-1])
			if cur == section {
				found = true
			}
			continue
		}
		if cur != section {
			continue
		}
		if i := strings.IndexByte(line, '='); i >= 0 {
			k := strings.ToLower(strings.TrimSpace(line[:i]))
			m[k] = strings.TrimSpace(line[i+1:])
		}
	}
	return m, found
}

// normalizeDconfBool converts a dconf boolean literal ("true"/"false") to the
// canonical observation value.
func normalizeDconfBool(v string) string {
	if strings.EqualFold(strings.TrimSpace(v), "true") {
		return "true"
	}
	return "false"
}

// stripDconfType removes a GVariant type prefix ("uint32 300" -> "300").
func stripDconfType(v string) string {
	v = strings.TrimSpace(v)
	if f := strings.Fields(v); len(f) == 2 && (f[0] == "uint32" || f[0] == "int32" || f[0] == "int64") {
		return f[1]
	}
	return v
}

// collectTLSLinux reports tls.* derived from a detected web-server config
// (partial tier — config-derived, never a live handshake, constraint #4).
// nginx: ssl_protocols / ssl_ciphers. Apache httpd: SSLProtocol /
// SSLCipherSuite.
func collectTLSLinux(nginxConf, httpdConf string) []Observation {
	minKey := familyTLS + ".min_version"
	cipherKey := familyTLS + ".ciphers"

	if data, sha, reason := readSource(nginxConf, maxConfigFileSize); reason == "" {
		proto := nginxDirective(data, "ssl_protocols")
		ciph := nginxDirective(data, "ssl_ciphers")
		return tlsObservations(minKey, cipherKey, nginxConf, sha, proto, ciph)
	}
	if data, sha, reason := readSource(httpdConf, maxConfigFileSize); reason == "" {
		proto := apacheDirective(data, "SSLProtocol")
		ciph := apacheDirective(data, "SSLCipherSuite")
		return tlsObservations(minKey, cipherKey, httpdConf, sha, proto, ciph)
	}
	return []Observation{
		obsError(minKey, familyTLS, nginxConf, "no web-server TLS config found"),
		obsError(cipherKey, familyTLS, nginxConf, "no web-server TLS config found"),
	}
}

// tlsObservations builds the min_version + ciphers observations, emitting
// unknown for a directive that was absent from an otherwise-readable config.
func tlsObservations(minKey, cipherKey, path, sha, proto, ciph string) []Observation {
	var out []Observation
	if proto != "" {
		out = append(out, obsValue(minKey, familyTLS, proto, path, sha))
	} else {
		out = append(out, obsError(minKey, familyTLS, path, "protocol directive not set"))
	}
	if ciph != "" {
		out = append(out, obsValue(cipherKey, familyTLS, ciph, path, sha))
	} else {
		out = append(out, obsError(cipherKey, familyTLS, path, "cipher directive not set"))
	}
	return out
}

// nginxDirective returns the value of an nginx `name value;` directive (last
// wins, trailing ';' stripped).
func nginxDirective(data []byte, name string) string {
	val := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(strings.TrimRight(line, ";"))
		if len(fields) >= 2 && fields[0] == name {
			val = strings.Join(fields[1:], " ")
		}
	}
	return val
}

// apacheDirective returns the value of an Apache `Name value` directive
// (case-insensitive name, last wins).
func apacheDirective(data []byte, name string) string {
	val := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], name) {
			val = strings.Join(fields[1:], " ")
		}
	}
	return val
}
