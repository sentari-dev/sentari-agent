package jvm

import (
	"os"
	"path/filepath"
	"testing"
)

// Each app-server discoverer follows the same three-case pattern:
// env-var happy path, env-var pointing at a non-server dir refused,
// and no-install-found returns empty.  Since the code paths are
// near-identical (serverSpec helper + per-server markers), one
// table-driven test harness covers all six — each row customises
// the per-server specifics.
//
// Server-specific marker files are created by ``setupMarker`` closures;
// the table keeps the test body uniform while letting each server's
// marker-shape quirks live near that server's row.

type serverFixture struct {
	name        string // for t.Run
	envVar      string
	layoutConst string
	markerFiles []string // relative paths to create (dirs auto-created)
}

// serverEnvironment is a shape-only alias used by runDiscoverer so the
// table body doesn't have to import scanner.Environment for each cast.
type serverEnvironment = struct {
	EnvType string
	Path    string
	Name    string
}

// fixtures covers every env var each discoverer actually consults so a
// typo or marker-expectation mismatch for any variant is caught here,
// not by a customer.  Tomcat: CATALINA_HOME only (CATALINA_BASE is not
// a binary root).  JBoss: all three alias vars.  Jetty: HOME + BASE
// (BASE also carries start.jar when a split install is in use).
func fixtures() []serverFixture {
	return []serverFixture{
		{
			name:        "tomcat-CATALINA_HOME",
			envVar:      "CATALINA_HOME",
			layoutConst: layoutTomcat,
			markerFiles: []string{"bin/catalina.sh"},
		},
		{
			name:        "jboss-JBOSS_HOME",
			envVar:      "JBOSS_HOME",
			layoutConst: layoutJBoss,
			markerFiles: []string{"bin/standalone.sh", "modules/placeholder"},
		},
		{
			name:        "jboss-WILDFLY_HOME",
			envVar:      "WILDFLY_HOME",
			layoutConst: layoutJBoss,
			markerFiles: []string{"bin/standalone.sh", "modules/placeholder"},
		},
		{
			name:        "jboss-EAP_HOME",
			envVar:      "EAP_HOME",
			layoutConst: layoutJBoss,
			markerFiles: []string{"bin/standalone.sh", "modules/placeholder"},
		},
		{
			name:        "weblogic-WL_HOME",
			envVar:      "WL_HOME",
			layoutConst: layoutWebLogic,
			markerFiles: []string{"server/bin/startWebLogic.sh"},
		},
		{
			name:        "websphere-WAS_HOME",
			envVar:      "WAS_HOME",
			layoutConst: layoutWebSphere,
			markerFiles: []string{"bin/versionInfo.sh"},
		},
		{
			name:        "jetty-JETTY_HOME",
			envVar:      "JETTY_HOME",
			layoutConst: layoutJetty,
			markerFiles: []string{"start.jar"},
		},
		{
			name:        "jetty-JETTY_BASE",
			envVar:      "JETTY_BASE",
			layoutConst: layoutJetty,
			markerFiles: []string{"start.jar"},
		},
		{
			name:        "glassfish-GLASSFISH_HOME",
			envVar:      "GLASSFISH_HOME",
			layoutConst: layoutGlassFish,
			markerFiles: []string{"bin/asadmin"},
		},
	}
}

// TestAppServerDiscoverers_EnvVarHappyPath: per server, set the env
// var to a directory with the marker files populated; discovery
// emits exactly one Environment for that path with the right layout
// tag and EnvType.
func TestAppServerDiscoverers_EnvVarHappyPath(t *testing.T) {
	for _, f := range fixtures() {
		t.Run(f.name, func(t *testing.T) {
			clearAllServerEnvs(t)
			tmp := t.TempDir()
			root := filepath.Join(tmp, f.name+"-home")
			seedMarkers(t, root, f.markerFiles)
			t.Setenv(f.envVar, root)

			envs := runDiscoverer(f.name)
			if len(envs) != 1 {
				t.Fatalf("%s: expected 1 Environment, got %d: %+v", f.name, len(envs), envs)
			}
			got := envs[0]
			if got.EnvType != EnvJVM {
				t.Errorf("%s: EnvType: got %q want %q", f.name, got.EnvType, EnvJVM)
			}
			if got.Name != f.layoutConst {
				t.Errorf("%s: Name: got %q want %q", f.name, got.Name, f.layoutConst)
			}
			if got.Path != root {
				t.Errorf("%s: Path: got %q want %q", f.name, got.Path, root)
			}
		})
	}
}

// TestAppServerDiscoverers_EnvVarRefusedOnNonMatchingDir: env var
// set to a directory that is NOT an install of that server (missing
// the marker files) returns zero Environments.  Guards against
// stray env vars causing arbitrary-directory scans.
func TestAppServerDiscoverers_EnvVarRefusedOnNonMatchingDir(t *testing.T) {
	for _, f := range fixtures() {
		t.Run(f.name, func(t *testing.T) {
			clearAllServerEnvs(t)
			tmp := t.TempDir()
			root := filepath.Join(tmp, "bogus")
			if err := os.MkdirAll(root, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			// Deliberately DO NOT create the marker files.
			t.Setenv(f.envVar, root)

			envs := runDiscoverer(f.name)
			if len(envs) != 0 {
				t.Fatalf("%s: expected 0 Environments when marker absent, got %d: %+v",
					f.name, len(envs), envs)
			}
		})
	}
}

// TestAppServerDiscoverers_NothingConfigured: with every server env
// var cleared AND the well-known-roots slices emptied, every
// discoverer MUST return an empty slice.  Previously we tolerated a
// non-empty result on CI images with real installs under /opt — but
// that made the test non-deterministic and effectively untestable.
// Now the well-known paths are forcibly empty so the assertion is
// strict.
func TestAppServerDiscoverers_NothingConfigured(t *testing.T) {
	// Zero out well-known parents for every app-server discoverer so
	// the test is hermetic on hosts with real installs under /opt
	// (common on CI Linux images).
	origTomcat := tomcatWellKnown
	origJBoss := jbossWellKnown
	origWebLogic := weblogicWellKnown
	origWebSphereAbs := websphereWellKnownAbs
	origJetty := jettyWellKnown
	origGlassFish := glassfishWellKnown
	t.Cleanup(func() {
		tomcatWellKnown = origTomcat
		jbossWellKnown = origJBoss
		weblogicWellKnown = origWebLogic
		websphereWellKnownAbs = origWebSphereAbs
		jettyWellKnown = origJetty
		glassfishWellKnown = origGlassFish
	})
	tomcatWellKnown = nil
	jbossWellKnown = nil
	weblogicWellKnown = nil
	websphereWellKnownAbs = nil
	jettyWellKnown = nil
	glassfishWellKnown = nil

	for _, f := range fixtures() {
		t.Run(f.name, func(t *testing.T) {
			clearAllServerEnvs(t)
			envs := runDiscoverer(f.name)
			if len(envs) != 0 {
				t.Fatalf("%s: expected 0 Environments with nothing configured, got %d: %+v",
					f.name, len(envs), envs)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// clearAllServerEnvs wipes every env var any discoverer consults so
// leakage between table rows is impossible.  Listed in one place so a
// new server's env var is added here AND the table above.
func clearAllServerEnvs(t *testing.T) {
	t.Helper()
	for _, v := range []string{
		// Workstation + JDK
		"MAVEN_HOME", "GRADLE_USER_HOME", "JAVA_HOME",
		// Tomcat — CATALINA_BASE is NOT consulted by the discoverer
		// (see note in discovery_tomcat.go) but we still clear it to
		// avoid leakage from the caller's environment into the test.
		"CATALINA_HOME", "CATALINA_BASE",
		// JBoss / WildFly / EAP
		"JBOSS_HOME", "WILDFLY_HOME", "EAP_HOME",
		// WebLogic — MW_HOME / DOMAIN_HOME are NOT consulted (see
		// note in discovery_weblogic.go) but we clear them anyway.
		"WL_HOME", "MW_HOME", "DOMAIN_HOME",
		// WebSphere
		"WAS_HOME",
		// Jetty
		"JETTY_HOME", "JETTY_BASE",
		// GlassFish / Payara
		"GLASSFISH_HOME", "PAYARA_HOME", "AS_INSTALL",
	} {
		t.Setenv(v, "")
	}
}

func seedMarkers(t *testing.T, root string, rels []string) {
	t.Helper()
	for _, rel := range rels {
		full := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir %q: %v", filepath.Dir(full), err)
		}
		if err := os.WriteFile(full, []byte("marker"), 0o755); err != nil {
			t.Fatalf("write marker %q: %v", full, err)
		}
	}
}

// runDiscoverer routes a fixture name (e.g. "jboss-WILDFLY_HOME") to
// the actual discoverer for that server family and converts the
// returned []scanner.Environment into the alias shape used by the
// table above.  Keeps the table rows free of type noise and lets one
// discoverer be exercised through multiple env-var columns.
func runDiscoverer(name string) []serverEnvironment {
	var raw []serverEnvironment
	convert := func(name, layout, path string) {
		raw = append(raw, serverEnvironment{
			EnvType: name,
			Name:    layout,
			Path:    path,
		})
	}
	// Fixture name format: "<server>-<ENVVAR>" (e.g. "jboss-JBOSS_HOME").
	// Dispatch on the prefix before the first '-'.
	server := name
	for i := 0; i < len(name); i++ {
		if name[i] == '-' {
			server = name[:i]
			break
		}
	}
	switch server {
	case "tomcat":
		for _, e := range discoverTomcat() {
			convert(e.EnvType, e.Name, e.Path)
		}
	case "jboss":
		for _, e := range discoverJBoss() {
			convert(e.EnvType, e.Name, e.Path)
		}
	case "weblogic":
		for _, e := range discoverWebLogic() {
			convert(e.EnvType, e.Name, e.Path)
		}
	case "websphere":
		for _, e := range discoverWebSphere() {
			convert(e.EnvType, e.Name, e.Path)
		}
	case "jetty":
		for _, e := range discoverJetty() {
			convert(e.EnvType, e.Name, e.Path)
		}
	case "glassfish":
		for _, e := range discoverGlassFish() {
			convert(e.EnvType, e.Name, e.Path)
		}
	}
	return raw
}
