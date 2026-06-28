package runtimeversions

import "testing"

func TestCycleFor_AppServers(t *testing.T) {
	cases := []struct{ name, version, want string }{
		{"wildfly", "40.0.1.Final", "40"},
		{"wildfly", "31.0.0.Final", "31"},
		{"tomcat", "10.1.18", "10"},
		{"payara", "6.2024.5", "6"},
		{"jboss-eap", "7.4.0.GA", "7.4"},
		{"jetty", "12.0.5", "12.0"},
		{"weblogic", "14.1.1", "unknown"},
		{"wildfly", "garbage", "unknown"},
	}
	for _, c := range cases {
		if got := CycleFor(c.name, c.version); got != c.want {
			t.Errorf("CycleFor(%q,%q)=%q want %q", c.name, c.version, got, c.want)
		}
	}
}
