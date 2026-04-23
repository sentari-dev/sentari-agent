package jvm

import "github.com/sentari-dev/sentari-agent/scanner"

// GlassFish / Payara — the Eclipse (formerly Oracle) reference impl
// of Jakarta EE, plus Payara, the commercial-supported fork.  Same
// on-disk layout because Payara started as a GlassFish fork and
// never diverged structurally.
//
// Env vars: GlassFish ships scripts that set ``GLASSFISH_HOME``;
// Payara's scripts set ``PAYARA_HOME``.  ``AS_INSTALL`` is the
// historic variable name from Sun days — still honoured by many
// operator scripts.  Single discoverer covers all three.
//
// Marker: ``bin/asadmin`` is unique to the GlassFish family (the
// admin CLI has had the same binary name since GlassFish v2).
//
// The scanDirTree walk from the install root picks up:
//   - modules/*.jar
//   - lib/*.jar
//   - domains/*/applications/**/*.{jar,war,ear}
//   - domains/*/lib/*.jar
func discoverGlassFish() []scanner.Environment {
	return discoverByServerSpec(serverSpec{
		layout:  layoutGlassFish,
		envVars: []string{"GLASSFISH_HOME", "PAYARA_HOME", "AS_INSTALL"},
		wellKnown: map[string][]string{
			"linux":  {"/opt"},
			"darwin": {"/opt", "/usr/local/opt"},
			"windows": {
				`C:\Program Files`,
				`C:\glassfish`,
				`C:\payara`,
			},
		},
		marker: func(root string) bool {
			return hasAny(root, "bin/asadmin", "bin/asadmin.bat")
		},
	})
}
