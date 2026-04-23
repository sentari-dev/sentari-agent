package jvm

import "github.com/sentari-dev/sentari-agent/scanner"

// IBM WebSphere Application Server (traditional — not Liberty).  Big
// in financial services; scanning matters because the shipped
// version of the JVM + IBM runtime libraries lags upstream and
// accumulates CVEs between IBM fixpacks.
//
// Install layout: always under ``AppServer/`` inside the WAS root.
// Libraries live at ``AppServer/lib/``, plugins at
// ``AppServer/plugins/``, customer applications at
// ``AppServer/profiles/*/installedApps/**``.  The shared
// scanDirTree walk from WAS_HOME picks up all of them.
//
// Marker: ``bin/versionInfo.sh`` is universal across WAS 7, 8, 8.5,
// 9 installs.  The binary marker ``AppServer/lib/startServer.jar``
// is an equivalent indicator.
func discoverWebSphere() []scanner.Environment {
	return discoverByServerSpec(serverSpec{
		layout:  layoutWebSphere,
		envVars: []string{"WAS_HOME"},
		wellKnownAbs: map[string][]string{
			"linux": {"/opt/IBM/WebSphere/AppServer"},
			"windows": {
				`C:\IBM\WebSphere\AppServer`,
				`C:\Program Files\IBM\WebSphere\AppServer`,
			},
		},
		marker: func(root string) bool {
			return hasAny(root,
				"bin/versionInfo.sh",
				"bin/versionInfo.bat",
				"lib/startServer.jar",
				"AppServer/bin/versionInfo.sh", // when WAS_HOME is the parent
			)
		},
	})
}
