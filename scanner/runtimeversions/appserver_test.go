package runtimeversions

import (
	"archive/zip"
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
	if r.Name != "wildfly" || r.Version != "40.0.1.Final" || r.Cycle != "40.0" {
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

// writeJarWithVersion writes a minimal JAR whose MANIFEST.MF carries the given
// Implementation-Version (for Tomcat / WebLogic version extraction tests).
func writeJarWithVersion(t *testing.T, path, version string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zw := zip.NewWriter(f)
	w, err := zw.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("Manifest-Version: 1.0\nImplementation-Version: " + version + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDetectAllAppServers_Tomcat(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "apache-tomcat-10.1.18")
	writeJarWithVersion(t, filepath.Join(home, "lib", "catalina.jar"), "10.1.18")
	got := DetectAllAppServers([]string{parent})
	if len(got) != 1 || got[0].Name != "tomcat" || got[0].Version != "10.1.18" || got[0].Cycle != "10.1" {
		t.Fatalf("got %+v", got)
	}
}

func TestDetectAllAppServers_Payara(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "payara6")
	writeTree(t, home, map[string]string{
		"glassfish/config/branding/glassfish-version.properties": "product_version=6.2024.5\n",
	})
	got := DetectAllAppServers([]string{parent})
	if len(got) != 1 || got[0].Name != "payara" || got[0].Version != "6.2024.5" || got[0].Cycle != "6.2024" {
		t.Fatalf("got %+v", got)
	}
}

func TestDetectAllAppServers_WebLogic(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "wls14")
	writeTree(t, home, map[string]string{"server/bin/startWebLogic.sh": "#!/bin/sh\n"})
	writeJarWithVersion(t, filepath.Join(home, "server", "lib", "weblogic.jar"), "14.1.1.0")
	got := DetectAllAppServers([]string{parent})
	if len(got) != 1 || got[0].Name != "weblogic" || got[0].Distro != "Oracle" {
		t.Fatalf("got %+v", got)
	}
}

func TestDetectAllAppServers_WebSpherePresenceOnly(t *testing.T) {
	parent := t.TempDir()
	home := filepath.Join(parent, "AppServer")
	writeTree(t, home, map[string]string{"bin/versionInfo.sh": "#!/bin/sh\n"})
	got := DetectAllAppServers([]string{parent})
	// Presence recorded even though version can't be read without running a binary.
	if len(got) != 1 || got[0].Name != "websphere" || got[0].Version != "unknown" || got[0].Distro != "IBM" {
		t.Fatalf("got %+v", got)
	}
}
