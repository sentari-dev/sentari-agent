package hardening

import (
	"path/filepath"
	"sort"
	"strings"
)

// sshKeywords maps the sshd_config directive (lowercased) to the observation
// slug the server catalog consumes. Only these directives are emitted.
var sshKeywords = map[string]string{
	"permitrootlogin":        "permit_root_login",
	"passwordauthentication": "password_authentication",
	"permitemptypasswords":   "permit_empty_passwords",
	"ciphers":                "ciphers",
	"macs":                   "macs",
	"kexalgorithms":          "kex_algorithms",
	"protocol":               "protocol",
	"x11forwarding":          "x11_forwarding",
	"maxauthtries":           "max_auth_tries",
	"logingracetime":         "login_grace_time",
	"clientaliveinterval":    "client_alive_interval",
}

// sshResolved records the first-obtained-wins value for one keyword and which
// file it came from.
type sshResolved struct {
	value      string
	sourcePath string
	sourceSHA  string
}

// collectSSH parses an sshd_config plus its Include globs (first-obtained-wins)
// and emits one observation per known keyword. A keyword seen only inside a
// Match block is emitted as `conditional (Match block)` -> unknown. An absent
// keyword is emitted as the `(default)` sentinel with default_assumed=true.
//
// mainConfigPath is real ("/etc/ssh/sshd_config") in production and a fixture
// path in tests. The parser reads every file through safeio (symlink-refusing).
func collectSSH(mainConfigPath string) []Observation {
	global := map[string]sshResolved{}
	matchOnly := map[string]bool{}

	// If the main config itself is unreadable, every key is unknown against it.
	mainData, mainSHA, reason := readSource(mainConfigPath, maxConfigFileSize)
	if reason != "" {
		out := make([]Observation, 0, len(sshKeywords))
		for _, slug := range sortedSlugs() {
			out = append(out, obsError(familySSH+"."+slug, familySSH, mainConfigPath, reason))
		}
		return out
	}

	visited := map[string]bool{}
	parseSSHDStream(mainConfigPath, mainData, mainSHA, global, matchOnly, visited, 0)

	out := make([]Observation, 0, len(sshKeywords))
	for _, slug := range sortedSlugs() {
		key := familySSH + "." + slug
		if r, ok := global[slug]; ok {
			out = append(out, obsValue(key, familySSH, r.value, r.sourcePath, r.sourceSHA))
			continue
		}
		if matchOnly[slug] {
			out = append(out, obsError(key, familySSH, mainConfigPath, "conditional (Match block)"))
			continue
		}
		// Unset anywhere -> documented "(default)" sentinel; the server scores
		// this `unknown` (it does NOT synthesize a PASS — see the contract's
		// conservative-default note).
		out = append(out, obsDefault(key, familySSH, "(default)", mainConfigPath, mainSHA))
	}
	return out
}

// parseSSHDStream processes one sshd_config file's lines in order, splicing in
// Include files at the point they appear (sshd semantics). First occurrence of
// a keyword in the GLOBAL context wins; a keyword seen only inside a Match block
// is recorded in matchOnly.
func parseSSHDStream(path string, data []byte, sha string, global map[string]sshResolved, matchOnly map[string]bool, visited map[string]bool, depth int) {
	if depth > 16 { // guard against Include cycles / pathological nesting
		return
	}
	abs, _ := filepath.Abs(path)
	if visited[abs] {
		return
	}
	visited[abs] = true

	inMatch := false
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keyword, value := splitSSHDLine(line)
		lk := strings.ToLower(keyword)

		switch lk {
		case "match":
			// `Match all` restores global context; any other selector opens a
			// conditional block.
			inMatch = !strings.EqualFold(strings.TrimSpace(value), "all")
			continue
		case "include":
			// Includes are processed inline; a keyword they set counts as
			// global unless we are currently inside a Match block.
			for _, inc := range expandSSHDIncludes(path, value) {
				incData, incSHA, reason := readSource(inc, maxConfigFileSize)
				if reason != "" {
					continue // unreadable include contributes nothing
				}
				parseSSHDStreamNested(inc, incData, incSHA, global, matchOnly, visited, depth+1, inMatch)
			}
			continue
		}

		slug, known := sshKeywords[lk]
		if !known {
			continue
		}
		if inMatch {
			matchOnly[slug] = true
			continue
		}
		if _, seen := global[slug]; !seen {
			global[slug] = sshResolved{value: value, sourcePath: path, sourceSHA: sha}
		}
	}
}

// parseSSHDStreamNested handles an included file that may be entered while the
// parent is already inside a Match block: in that case every keyword the
// include sets is conditional too.
func parseSSHDStreamNested(path string, data []byte, sha string, global map[string]sshResolved, matchOnly map[string]bool, visited map[string]bool, depth int, parentInMatch bool) {
	if parentInMatch {
		// Whole include inherits the conditional context; mark any known
		// keyword it sets as match-only, but still recurse for nested Includes.
		markIncludeConditional(path, data, matchOnly, visited, depth)
		return
	}
	parseSSHDStream(path, data, sha, global, matchOnly, visited, depth)
}

// markIncludeConditional records every known keyword in an include (entered
// under a parent Match block) as conditional-only.
func markIncludeConditional(path string, data []byte, matchOnly map[string]bool, visited map[string]bool, depth int) {
	abs, _ := filepath.Abs(path)
	if visited[abs] {
		return
	}
	visited[abs] = true
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keyword, _ := splitSSHDLine(line)
		if slug, known := sshKeywords[strings.ToLower(keyword)]; known {
			matchOnly[slug] = true
		}
	}
}

// splitSSHDLine splits a directive line into keyword and value. sshd_config
// separates them by whitespace (an optional `=` is also accepted). The value is
// the trimmed remainder, with surrounding quotes stripped.
func splitSSHDLine(line string) (keyword, value string) {
	// Handle "Key=Value" and "Key Value" / "Key = Value".
	if i := strings.IndexAny(line, " \t="); i >= 0 {
		keyword = line[:i]
		value = strings.TrimSpace(strings.TrimLeft(line[i:], " \t="))
	} else {
		keyword = line
	}
	value = strings.Trim(value, `"`)
	return keyword, value
}

// expandSSHDIncludes resolves an `Include` directive's glob patterns. A relative
// pattern resolves against the directory of the including file (sshd uses
// /etc/ssh, which is that directory for the main config). Results are sorted for
// determinism.
func expandSSHDIncludes(parentPath, patterns string) []string {
	base := filepath.Dir(parentPath)
	var out []string
	for _, pat := range strings.Fields(patterns) {
		pat = strings.Trim(pat, `"`)
		if !filepath.IsAbs(pat) {
			pat = filepath.Join(base, pat)
		}
		matches, err := filepath.Glob(pat)
		if err != nil {
			continue
		}
		sort.Strings(matches)
		out = append(out, matches...)
	}
	return out
}

// sortedSlugs returns the SSH observation slugs in a stable order.
func sortedSlugs() []string {
	slugs := make([]string, 0, len(sshKeywords))
	for _, s := range sshKeywords {
		slugs = append(slugs, s)
	}
	sort.Strings(slugs)
	return slugs
}
