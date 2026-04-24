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
// websphereWellKnownAbs — see note in tomcatWellKnown.  WebSphere
// ships at a fixed install path per vendor convention; no parent
// walking is needed.
var websphereWellKnownAbs = map[string][]string{
	"linux": {"/opt/IBM/WebSphere/AppServer"},
	"windows": {
		`C:\IBM\WebSphere\AppServer`,
		`C:\Program Files\IBM\WebSphere\AppServer`,
	},
}

func discoverWebSphere() []scanner.Environment {
	return discoverByServerSpec(serverSpec{
		layout:       layoutWebSphere,
		envVars:      []string{"WAS_HOME"},
		wellKnownAbs: websphereWellKnownAbs,
		// Marker expects WAS_HOME to name the AppServer directory
		// directly (IBM's own docs say this: WAS_HOME=.../AppServer).
		// We intentionally do NOT accept ``AppServer/bin/versionInfo.*``
		// here — if the parent matched, discoverByServerSpec would
		// emit the parent as the scan root, and scanDirTree would then
		// walk unrelated siblings.  Operators with WAS_HOME pointing
		// at the parent should point it at .../AppServer instead.
		marker: func(root string) bool {
			return hasAny(root,
				"bin/versionInfo.sh",
				"bin/versionInfo.bat",
				"lib/startServer.jar",
			)
		},
	})
}
