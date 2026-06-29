package runtimeversions

import (
	"path/filepath"
	"testing"
)

// If someone changes the WildFly marker (version.txt + standalone script),
// this fails loudly — the jvm package's discover_jboss.go uses the same
// markers (bin/standalone.sh + modules/) and the two must not drift.
func TestAppServerMarkers_WildFlyStable(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "wildfly-31.0.0.Final")
	writeTree(t, home, map[string]string{
		"version.txt":       "WildFly - Version 31.0.0.Final",
		"bin/standalone.sh": "#!/bin/sh\n",
		"modules/.keep":     "",
	})
	got := DetectAllAppServers([]string{parent})
	if len(got) != 1 || got[0].Name != "wildfly" || got[0].Cycle != "31.0" {
		t.Fatalf("WildFly marker/version drift: %+v", got)
	}
}
