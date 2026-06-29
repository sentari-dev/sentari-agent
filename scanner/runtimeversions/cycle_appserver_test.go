package runtimeversions

import "testing"

func TestCycleFor_AppServers(t *testing.T) {
	// App-server cycle is a best-effort fallback (major.minor, then major); the
	// server resolves the authoritative cohort against the feed. Must match
	// server/services/runtime_eol_cycle.py cycle_for.
	cases := []struct{ name, version, want string }{
		{"wildfly", "40.0.1.Final", "40.0"},
		{"wildfly", "31.0.0.Final", "31.0"},
		{"tomcat", "10.1.18", "10.1"},
		{"payara", "6.2024.5", "6.2024"},
		{"jboss-eap", "7.4.0.GA", "7.4"},
		{"jetty", "12.0.5", "12.0"},
		{"jetty", "11", "11"}, // major-only when no minor present
		{"weblogic", "14.1.1.0", "14.1"},
		{"websphere", "9.0.5.0", "9.0"},
		{"wildfly", "garbage", "unknown"},
	}
	for _, c := range cases {
		if got := CycleFor(c.name, c.version); got != c.want {
			t.Errorf("CycleFor(%q,%q)=%q want %q", c.name, c.version, got, c.want)
		}
	}
}
