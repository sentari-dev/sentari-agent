package jvm

import "github.com/sentari-dev/sentari-agent/scanner"

// Oracle WebLogic Server — the big-iron Java EE server common in
// banking, telco, public sector.  Install layout differs from the
// open-source servers because of Oracle's tooling: WL_HOME is the
// server binaries (server/, modules/), MW_HOME is the Middleware
// home one level up, DOMAIN_HOME is a configured domain.
//
// We prefer WL_HOME for scanning: it contains every shipped JAR.
// Domain-local lib/ is picked up via the scanDirTree walk under the
// same root because customer domains conventionally live at
// ``$WL_HOME/user_projects/domains/<name>`` — which sits inside the
// WL_HOME tree.  Out-of-tree DOMAIN_HOME installs are caught by the
// explicit env-var path.
//
// Marker: WebLogic's classic entry script ``server/bin/startWebLogic.sh``
// is present in every 10.3+ install.  ``server/lib/weblogic.jar`` is
// the definitive binary marker.  We check for either.
func discoverWebLogic() []scanner.Environment {
	return discoverByServerSpec(serverSpec{
		layout:  layoutWebLogic,
		envVars: []string{"WL_HOME", "MW_HOME", "DOMAIN_HOME"},
		wellKnown: map[string][]string{
			"linux":  {"/u01/app/oracle/product", "/opt/oracle"},
			"darwin": {"/opt/oracle"},
			"windows": {
				`C:\Oracle\Middleware`,
			},
		},
		marker: func(root string) bool {
			return hasAny(root,
				"server/bin/startWebLogic.sh",
				"server/bin/startWebLogic.cmd",
				"server/lib/weblogic.jar",
			)
		},
	})
}
