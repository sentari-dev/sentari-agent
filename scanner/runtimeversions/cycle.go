package runtimeversions

import "regexp"

var (
	pythonRe     = regexp.MustCompile(`^(\d+)\.(\d+)`)
	nodeRe       = regexp.MustCompile(`^(\d+)`)
	jdkLegacyRe  = regexp.MustCompile(`^1\.(\d+)`)
	jdkModernRe  = regexp.MustCompile(`^(\d+)`)
	majorRe      = regexp.MustCompile(`^(\d+)\b`)
	majorMinorRe = regexp.MustCompile(`^(\d+)\.(\d+)\b`)
)

// appServers is the set of JVM application-server runtime names. Their cycle is
// derived best-effort here; the server resolves the authoritative cohort against
// the synced endoflife.date feed (its granularity is inconsistent per product,
// so a fixed regex cannot derive it — see runtime_eol_cycle.py resolve_feed_cycle).
var appServers = map[string]bool{
	"wildfly": true, "jboss-eap": true, "tomcat": true,
	"jetty": true, "payara": true, "weblogic": true, "websphere": true,
}

// CycleFor returns the EOL cycle for a (runtime, version) tuple, or "unknown" on
// parse failure. Language-runtime derivation matches the server's
// EOL-cycle derivation exactly. App-server derivation is a
// best-effort fallback (major.minor, then major) the server may override.
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
	default:
		if appServers[runtime] {
			if m := majorMinorRe.FindStringSubmatch(version); m != nil {
				return m[1] + "." + m[2]
			}
			if m := majorRe.FindStringSubmatch(version); m != nil {
				return m[1]
			}
		}
	}
	return "unknown"
}
