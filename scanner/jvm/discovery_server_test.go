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
	name         string // for t.Run
	envVar       string
	layoutConst  string
	markerFiles  []string // relative paths to create (dirs auto-created)
	discoverFunc func() []serverEnvironment
}

// serverEnvironment is a shape-only alias so this file doesn't need
// to import the scanner package just for the assertion loop.
type serverEnvironment = struct {
	EnvType string
	Path    string
	Name    string
}

func fixtures() []serverFixture {
	// Wrap each discoverer so the test table sees a uniform
	// signature.  (Can't store the raw functions directly because
	// they return scanner.Environment and the test file above already
	// imports the scanner package where needed.)
	toAlias := func(envs interface{ Len() int }) []serverEnvironment {
		return nil // unused — we compare via the real discoverer below
	}
	_ = toAlias

	return []serverFixture{
		{
			name:        "tomcat",
			envVar:      "CATALINA_HOME",
			layoutConst: layoutTomcat,
			markerFiles: []string{"bin/catalina.sh"},
		},
		{
			name:        "jboss",
			envVar:      "JBOSS_HOME",
			layoutConst: layoutJBoss,
			markerFiles: []string{"bin/standalone.sh", "modules/placeholder"},
		},
		{
			name:        "weblogic",
			envVar:      "WL_HOME",
			layoutConst: layoutWebLogic,
			markerFiles: []string{"server/bin/startWebLogic.sh"},
		},
		{
			name:        "websphere",
			envVar:      "WAS_HOME",
			layoutConst: layoutWebSphere,
			markerFiles: []string{"bin/versionInfo.sh"},
		},
		{
			name:        "jetty",
			envVar:      "JETTY_HOME",
			layoutConst: layoutJetty,
			markerFiles: []string{"start.jar"},
		},
		{
			name:        "glassfish",
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
// var cleared and no well-known paths hit (tests run under t.TempDir
// so /opt/tomcat etc. are either absent or out of reach), the
// discoverer returns empty.
func TestAppServerDiscoverers_NothingConfigured(t *testing.T) {
	for _, f := range fixtures() {
		t.Run(f.name, func(t *testing.T) {
			clearAllServerEnvs(t)
			envs := runDiscoverer(f.name)
			// On a CI host with real Tomcat/WildFly installed under
			// /opt this could return non-empty.  We allow it — the
			// scenario is unusual enough that we'd rather document
			// than skip the test entirely.  What we MUST NOT see is
			// a panic or a wrong layout tag.
			for _, e := range envs {
				if e.Name != f.layoutConst {
					t.Errorf("%s: unexpected layout %q in %+v", f.name, e.Name, e)
				}
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
		// Tomcat
		"CATALINA_HOME", "CATALINA_BASE",
		// JBoss / WildFly / EAP
		"JBOSS_HOME", "WILDFLY_HOME", "EAP_HOME",
		// WebLogic
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

// runDiscoverer routes the string name to the actual discoverer and
// converts the returned []scanner.Environment into the alias shape
// used by the table above.  Keeps the table rows free of type noise.
func runDiscoverer(name string) []serverEnvironment {
	var raw []serverEnvironment
	convert := func(name, layout, path string) {
		raw = append(raw, serverEnvironment{
			EnvType: name,
			Name:    layout,
			Path:    path,
		})
	}
	switch name {
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
