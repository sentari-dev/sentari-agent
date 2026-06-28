package runtimeversions

import "regexp"

var (
	pythonRe        = regexp.MustCompile(`^(\d+)\.(\d+)`)
	nodeRe          = regexp.MustCompile(`^(\d+)`)
	jdkLegacyRe     = regexp.MustCompile(`^1\.(\d+)`)
	jdkModernRe     = regexp.MustCompile(`^(\d+)`)
	_MAJOR_RE       = regexp.MustCompile(`^(\d+)\b`)
	_MAJOR_MINOR_RE = regexp.MustCompile(`^(\d+)\.(\d+)\b`)
)

// CycleFor returns the EOL cycle for a (runtime, version) tuple, or
// "unknown" on parse failure. Same regex as the server's
// server/services/runtime_eol_cycle.py — both sides MUST agree.
func CycleFor(runtime, version string) string {
	switch runtime {
	case "python":
		if m := pythonRe.FindStringSubmatch(version); m != nil {
			return m[1] + "." + m[2]
		}
	case "node":
		if m := nodeRe.FindStringSubmatch(version); m != nil {
			return m[1]
		}
	case "jdk":
		if m := jdkLegacyRe.FindStringSubmatch(version); m != nil {
			return m[1]
		}
		if m := jdkModernRe.FindStringSubmatch(version); m != nil {
			return m[1]
		}
	case "wildfly", "tomcat", "payara":
		if m := _MAJOR_RE.FindStringSubmatch(version); m != nil {
			return m[1]
		}
		return "unknown"
	case "jboss-eap", "jetty":
		if m := _MAJOR_MINOR_RE.FindStringSubmatch(version); m != nil {
			return m[1] + "." + m[2]
		}
		return "unknown"
	}
	return "unknown"
}
