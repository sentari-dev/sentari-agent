package runtimeversions

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTree creates files under root from a map of relpath->content.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDetectAllAppServers_WildFly(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "wildfly-40.0.1.Final")
	writeTree(t, home, map[string]string{
		"version.txt":       "WildFly - Version 40.0.1.Final",
		"bin/standalone.sh": "#!/bin/sh\n",
		"bin/product.conf":  "slot=main\n",
		"modules/.keep":     "",
	})
	got := DetectAllAppServers([]string{parent})
	if len(got) != 1 {
		t.Fatalf("want 1 runtime, got %d: %+v", len(got), got)
	}
	r := got[0]
	if r.Name != "wildfly" || r.Version != "40.0.1.Final" || r.Cycle != "40" {
		t.Errorf("got %+v", r)
	}
	if r.InstallPath != home {
		t.Errorf("install path = %q want %q", r.InstallPath, home)
	}
}

func TestDetectAllAppServers_EAPviaProductConf(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "jboss-eap-7.4")
	writeTree(t, home, map[string]string{
		"version.txt":       "Red Hat JBoss Enterprise Application Platform - Version 7.4.0.GA",
		"bin/standalone.sh": "#!/bin/sh\n",
		"bin/product.conf":  "slot=eap\n",
		"modules/.keep":     "",
	})
	got := DetectAllAppServers([]string{parent})
	if len(got) != 1 || got[0].Name != "jboss-eap" || got[0].Cycle != "7.4" {
		t.Fatalf("got %+v", got)
	}
}

func TestDetectAllAppServers_Jetty(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "jetty-home-12.0.5")
	writeTree(t, home, map[string]string{
		"VERSION.txt": "jetty-12.0.5 - 20 December 2023\n",
		"start.jar":   "PK\x03\x04",
	})
	got := DetectAllAppServers([]string{parent})
	if len(got) != 1 || got[0].Name != "jetty" || got[0].Version != "12.0.5" || got[0].Cycle != "12.0" {
		t.Fatalf("got %+v", got)
	}
}

func TestDetectAllAppServers_JettyNoVersionTxt(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "jetty-home-12.0.5")
	writeTree(t, home, map[string]string{
		"start.jar":                   "PK\x03\x04",
		"lib/jetty-server-12.0.5.jar": "PK\x03\x04",
		"etc/jetty.xml":               "<Configure/>",
	})
	got := DetectAllAppServers([]string{parent})
	if len(got) != 1 || got[0].Name != "jetty" || got[0].Version != "12.0.5" || got[0].Cycle != "12.0" {
		t.Fatalf("got %+v", got)
	}
}

func TestDetectAllAppServers_VersionUnknownStillEmitted(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "wildfly-broken")
	writeTree(t, home, map[string]string{
		"version.txt":       "garbled nonsense with no version token here",
		"bin/standalone.sh": "#!/bin/sh\n",
		"modules/.keep":     "",
	})
	got := DetectAllAppServers([]string{parent})
	if len(got) != 1 || got[0].Version != "unknown" || got[0].Cycle != "unknown" {
		t.Fatalf("want presence with unknown version, got %+v", got)
	}
}
