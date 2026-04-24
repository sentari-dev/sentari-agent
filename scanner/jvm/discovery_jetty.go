package jvm

import "github.com/sentari-dev/sentari-agent/scanner"

// Eclipse Jetty — embedded in countless CI tools and developer
// stacks (Hudson/Jenkins early days, Eclipse IDE, Spring Boot with
// Jetty embedded, Gerrit, SonarQube, …).  Catching Jetty is valuable
// precisely because it's so widely embedded: a Jetty CVE like
// CVE-2023-26048 affects every tool that hasn't refreshed its embed.
//
// Env vars:
//   - JETTY_HOME — the install root with binaries + default config
//   - JETTY_BASE — a customer's overlay (different lib/ext/, etc.)
//
// Marker: ``start.jar`` at the install root is present in every
// Jetty distribution since 7.  ``lib/jetty-*.jar`` is the binary
// equivalent check.
// jettyWellKnown — see note in tomcatWellKnown.
var jettyWellKnown = map[string][]string{
	"linux":  {"/opt", "/usr/share", "/var/lib"},
	"darwin": {"/opt", "/usr/local/opt"},
	"windows": {
		`C:\Program Files\Eclipse Foundation`,
	},
}

func discoverJetty() []scanner.Environment {
	return discoverByServerSpec(serverSpec{
		layout:    layoutJetty,
		envVars:   []string{"JETTY_HOME", "JETTY_BASE"},
		wellKnown: jettyWellKnown,
		marker: func(root string) bool {
			// start.jar is the universal Jetty marker; etc/jetty.xml
			// is the fallback for stripped installs.  "lib" alone
			// would false-positive on every directory that happens
			// to contain a lib/ subtree.
			return hasAny(root, "start.jar", "etc/jetty.xml", "etc/jetty-http.xml")
		},
	})
}
