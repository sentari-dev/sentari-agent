package jvm

import "github.com/sentari-dev/sentari-agent/scanner"

// JBoss / WildFly / Red Hat JBoss EAP — same codebase, three brand
// names over its history.  All three identify themselves with
// ``bin/standalone.sh`` + a ``modules/`` directory; those two
// together are unambiguous.
//
// Env vars:
//   - JBOSS_HOME  — classic, still set by most installer scripts
//   - WILDFLY_HOME — modern Red Hat-provided install scripts
//   - EAP_HOME    — Red Hat EAP commercial packaging
//
// The shared scanDirTree walk picks up every module + deployment:
//   - modules/system/layers/base/**/*.jar
//   - modules/**/main/*.jar
//   - standalone/deployments/**/*.{jar,war,ear}
//   - domain/deployments/**/*.{jar,war,ear}
//
// Nested .ear/.war entries get descended into by the nested-jar
// traversal (PR #6), so every bundled library surfaces as its own
// PackageRecord.
// jbossWellKnown — see note in tomcatWellKnown.  Previously this
// included ``C:\`` directly which forced a listing of the Windows
// system drive root; narrowed to specific parents that every real
// Red Hat / WildFly installer uses.
var jbossWellKnown = map[string][]string{
	"linux":  {"/opt", "/usr/share"},
	"darwin": {"/opt", "/usr/local/opt"},
	"windows": {
		`C:\Program Files`,
		`C:\Program Files\Red Hat`,
		`C:\wildfly`,
		`C:\jboss`,
	},
}

func discoverJBoss() []scanner.Environment {
	return discoverByServerSpec(serverSpec{
		layout:    layoutJBoss,
		envVars:   []string{"JBOSS_HOME", "WILDFLY_HOME", "EAP_HOME"},
		wellKnown: jbossWellKnown,
		marker: func(root string) bool {
			// Both markers must be present so the check doesn't
			// false-positive on random ``bin/standalone.sh`` scripts.
			// The ``modules/`` entry must be a directory — a regular
			// file named ``modules`` would otherwise satisfy hasAny
			// and produce a false positive on wrapper shell scripts.
			return hasAny(root, "bin/standalone.sh", "bin/standalone.bat") &&
				hasAnyDir(root, "modules")
		},
	})
}
