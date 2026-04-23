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
func discoverTomcat() []scanner.Environment {
	return discoverByServerSpec(serverSpec{
		layout:  layoutTomcat,
		envVars: []string{"CATALINA_HOME", "CATALINA_BASE"},
		wellKnown: map[string][]string{
			"linux":  {"/opt", "/usr/share", "/var/lib"},
			"darwin": {"/opt", "/usr/local/opt"},
			"windows": {
				`C:\Program Files\Apache Software Foundation`,
				`C:\Tomcat`,
			},
		},
		marker: func(root string) bool {
			return hasAny(root, "bin/catalina.sh", "bin/catalina.bat")
		},
	})
}
