package jvm

import "github.com/sentari-dev/sentari-agent/scanner"

// Oracle WebLogic Server — the big-iron Java EE server common in
// banking, telco, public sector.  Install layout: WL_HOME is the
// server binaries (server/bin, server/lib), MW_HOME is the
// Middleware home one level up, DOMAIN_HOME is a configured domain.
//
// We only consult WL_HOME here.  MW_HOME and DOMAIN_HOME don't share
// the WL_HOME marker shape: MW_HOME contains a wlserver/ subtree (the
// actual WL_HOME); DOMAIN_HOME carries config/config.xml +
// servers/<name>/ but no server/bin/startWebLogic.*.  A future
// discoverer that accepts those shapes can add them without forcing
// the current WL_HOME check to misbehave.  Previously including them
// with the WL_HOME marker produced only silent refusals.
//
// Marker: WebLogic's classic entry script ``server/bin/startWebLogic.sh``
// is present in every 10.3+ install.  ``server/lib/weblogic.jar`` is
// the definitive binary marker.  We check for either.
// weblogicWellKnown — see note in tomcatWellKnown.
var weblogicWellKnown = map[string][]string{
	"linux":  {"/u01/app/oracle/product", "/opt/oracle"},
	"darwin": {"/opt/oracle"},
	"windows": {
		`C:\Oracle\Middleware`,
	},
}

func discoverWebLogic() []scanner.Environment {
	return discoverByServerSpec(serverSpec{
		layout:    layoutWebLogic,
		envVars:   []string{"WL_HOME"},
		wellKnown: weblogicWellKnown,
		marker: func(root string) bool {
			return hasAny(root,
				"server/bin/startWebLogic.sh",
				"server/bin/startWebLogic.cmd",
				"server/lib/weblogic.jar",
			)
		},
	})
}
