package runtimeversions

import (
	"regexp"
	"sort"
)

// Language-runtime name constants. These are the single source of the names
// the agent places in InstalledRuntime.Name for language runtimes; the
// producing detectors (python.go, python_system.go, node.go, jdk.go) reference
// them, and the v3-contract drift guard derives its emitted-name set from
// LanguageRuntimeNames() rather than a hand-maintained literal list.
const (
	RuntimePython = "python"
	RuntimeNode   = "node"
	RuntimeJDK    = "jdk"
)

// LanguageRuntimeNames returns the language-runtime names the agent can emit,
// in stable display order.
func LanguageRuntimeNames() []string {
	return []string{RuntimePython, RuntimeNode, RuntimeJDK}
}

// AppServerRuntimeNames returns the sorted set of JVM application-server
// runtime names the agent can emit — the keys of the appServers map, which is
// the single source classify() (appserver.go) draws its identities from.
//
// The v3-contract drift guard derives its cross-check set from this, so adding
// a new app-server value to appServers automatically forces the shared schema
// enum (docs/contracts/agent-scan-payload-v3.json) to list it or the guard
// fails — the class of drift that let "glassfish" ship unlisted (round 8).
func AppServerRuntimeNames() []string {
	names := make([]string, 0, len(appServers))
	for n := range appServers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

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
	"jetty": true, "payara": true, "glassfish": true,
	"weblogic": true, "websphere": true,
}

// CycleFor returns the EOL cycle for a (runtime, version) tuple, or "unknown" on
// parse failure. Language-runtime derivation matches the server's
// server/services/runtime_eol_cycle.py exactly. App-server derivation is a
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
