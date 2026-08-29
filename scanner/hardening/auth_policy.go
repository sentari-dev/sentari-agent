package hardening

import (
	"strings"
)

// collectAuthPolicy reads the local password / lockout policy from
// /etc/login.defs (pass_max_days, pass_min_days), the pwquality config
// (pass_min_len, pass_min_class) and the faillock config (faillock_deny,
// faillock_unlock_time). Each source is independent: an absent source yields
// unknown for only the keys it feeds.
func collectAuthPolicy(loginDefsPath, pwqualityPath, faillockPath string) []Observation {
	var out []Observation

	// login.defs — shell-style "KEY value" lines.
	ld, ldSHA, ldReason := readSource(loginDefsPath, maxConfigFileSize)
	ldKV := parseSpaceKV(ld)
	out = append(out,
		emitAuthKey("pass_max_days", loginDefsPath, ldSHA, ldReason, ldKV, "PASS_MAX_DAYS"),
		emitAuthKey("pass_min_days", loginDefsPath, ldSHA, ldReason, ldKV, "PASS_MIN_DAYS"),
	)

	// pwquality.conf — "key = value" lines.
	pq, pqSHA, pqReason := readSource(pwqualityPath, maxConfigFileSize)
	pqKV := parseEqualsKV(pq)
	out = append(out,
		emitAuthKey("pass_min_len", pwqualityPath, pqSHA, pqReason, pqKV, "minlen"),
		emitAuthKey("pass_min_class", pwqualityPath, pqSHA, pqReason, pqKV, "minclass"),
	)

	// faillock.conf — "key = value" or bare "key".
	fl, flSHA, flReason := readSource(faillockPath, maxConfigFileSize)
	flKV := parseEqualsKV(fl)
	out = append(out,
		emitAuthKey("faillock_deny", faillockPath, flSHA, flReason, flKV, "deny"),
		emitAuthKey("faillock_unlock_time", faillockPath, flSHA, flReason, flKV, "unlock_time"),
	)
	return out
}

// emitAuthKey builds one auth_policy observation: unknown when the source was
// unreadable, unknown ("not set") when the source was readable but the key was
// absent, else the parsed value.
func emitAuthKey(slug, sourcePath, sha, reason string, kv map[string]string, srcKey string) Observation {
	key := familyAuthPolicy + "." + slug
	if reason != "" {
		return obsError(key, familyAuthPolicy, sourcePath, reason)
	}
	v, ok := kv[strings.ToLower(srcKey)]
	if !ok {
		return obsError(key, familyAuthPolicy, sourcePath, "not set")
	}
	return obsValue(key, familyAuthPolicy, v, sourcePath, sha)
}

// parseSpaceKV parses "KEY value" whitespace-separated config lines
// (login.defs). Keys are lowercased. First occurrence wins.
func parseSpaceKV(data []byte) map[string]string {
	m := map[string]string{}
	if data == nil {
		return m
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		k := strings.ToLower(fields[0])
		if _, seen := m[k]; !seen {
			m[k] = fields[1]
		}
	}
	return m
}

// parseEqualsKV parses "key = value" (or "key=value", or bare "key") config
// lines. Keys are lowercased. First occurrence wins. A bare key (faillock's
// audit/silent style) maps to "true".
func parseEqualsKV(data []byte) map[string]string {
	m := map[string]string{}
	if data == nil {
		return m
	}
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var k, v string
		if i := strings.IndexByte(line, '='); i >= 0 {
			k = strings.ToLower(strings.TrimSpace(line[:i]))
			v = strings.TrimSpace(line[i+1:])
		} else {
			k = strings.ToLower(strings.Fields(line)[0])
			v = "true"
		}
		if k == "" {
			continue
		}
		if _, seen := m[k]; !seen {
			m[k] = v
		}
	}
	return m
}
