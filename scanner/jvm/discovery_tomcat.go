package jvm

import "github.com/sentari-dev/sentari-agent/scanner"

// Tomcat — the Apache servlet container.  Layout markers: Tomcat
// always ships ``bin/catalina.sh`` on POSIX + ``bin/catalina.bat`` on
// Windows.  Either alone is sufficient; checking for both is
// redundant (distro packaging strips whichever doesn't apply).
//
// Walking the install root recursively via scanDirTree picks up:
//   - ``lib/*.jar`` (Tomcat's own library dir)
//   - ``webapps/**/WEB-INF/lib/*.jar`` (deployed applications' libs)
//
// No per-server walker needed; the shared scanDirTree handles both.
//
// Note: we intentionally do NOT consult CATALINA_BASE here.  In split
// home/base deployments, CATALINA_BASE is the per-instance writable
// tree that carries conf/, logs/, webapps/ — but not bin/catalina.*.
// It's reached by walking CATALINA_HOME's webapps/ subtree, or by a
// future discoverer that accepts base-shaped directories (conf/
// server.xml + webapps/).  Including CATALINA_BASE with the current
// marker only produces silent refusals.
// tomcatWellKnown is the per-OS list of parent directories that may
// contain a Tomcat install (one level deep).  Package-level var so
// tests can temporarily clear it for hermeticity.
var tomcatWellKnown = map[string][]string{
	"linux":  {"/opt", "/usr/share", "/var/lib"},
	"darwin": {"/opt", "/usr/local/opt"},
	"windows": {
		`C:\Program Files\Apache Software Foundation`,
		`C:\Tomcat`,
	},
}

func discoverTomcat() []scanner.Environment {
	return discoverByServerSpec(serverSpec{
		layout:    layoutTomcat,
		envVars:   []string{"CATALINA_HOME"},
		wellKnown: tomcatWellKnown,
		marker: func(root string) bool {
			return hasAny(root, "bin/catalina.sh", "bin/catalina.bat")
		},
	})
}
