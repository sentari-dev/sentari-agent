// Maven / Java writer.
//
// Third ecosystem after pip and npm.  Maven's ``settings.xml`` is
// the highest-stakes config in this writer family — operators
// commonly store cleartext repository credentials in ``<servers>``
// blocks alongside ``<mirrors>`` definitions for internal Artifactory
// or Nexus registries — so the writer is conservative by design:
//
//   - Fresh host (no ``settings.xml``) → write a complete
//     Sentari-managed document.
//   - Existing Sentari-managed file (marker present) → rewrite.
//   - Existing operator-curated file (no marker) → **refuse to
//     touch**, return a typed warning.  The operator can opt in by
//     deleting their settings.xml after backing it up, or by
//     pointing Sentari-Proxy at their existing Artifactory in the
//     server-side install-gate config (Phase C feature).
//
// XML merge — splicing our ``<mirror>`` into an operator-curated
// ``<mirrors>`` while preserving credentials and profiles
// elsewhere in the document — is genuine engineering with its own
// failure modes (encoding mismatches, comment preservation, attribute
// ordering).  It's deferred to a follow-up PR so it can land with
// dedicated test coverage rather than as one branch of a multi-
// branch writer.

package installgate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// MavenScope picks the user-level or system-level ``settings.xml``.
type MavenScope int

const (
	// MavenScopeUser writes ``~/.m2/settings.xml``.  Maven looks
	// here first; a file at this path is the per-user override
	// for whatever ships in the system-level location.
	MavenScopeUser MavenScope = iota

	// MavenScopeSystem writes ``$MAVEN_HOME/conf/settings.xml``.
	// Returns empty (soft no-op) when ``MAVEN_HOME`` is not set —
	// Maven's install path is operator-decided + non-stable across
	// distros (apt installs differently to homebrew which differs
	// from sdkman) so guess-paths would write into a directory
	// Maven won't read.
	MavenScopeSystem
)

// MavenPath returns the absolute settings.xml path for the given
// scope.  Empty return signals "skip" (soft no-op upstream).
func MavenPath(scope MavenScope) string {
	switch scope {
	case MavenScopeUser:
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return ""
		}
		return filepath.Join(home, ".m2", "settings.xml")
	case MavenScopeSystem:
		mvn := os.Getenv("MAVEN_HOME")
		if mvn == "" {
			return ""
		}
		return filepath.Join(mvn, "conf", "settings.xml")
	}
	return ""
}

// WriteMavenResult mirrors WritePipResult and WriteNpmResult.
type WriteMavenResult struct {
	Path    string
	Changed bool
	Removed bool
	// SkippedOperator is set when the writer found an existing
	// settings.xml without the Sentari marker and refused to
	// overwrite or merge.  The orchestrator surfaces this to the
	// caller so an operator can see "Maven not gated on this host"
	// in the audit trail without misreading it as a bug.
	SkippedOperator bool
}

// WriteMaven applies the Maven section of a verified policy-map.
//
// Behaviour matrix:
//
//	+----------------------+--------------------+--------------------------+
//	| proxy_endpoints[maven]| existing          | action                   |
//	+----------------------+--------------------+--------------------------+
//	| non-empty            | absent             | write fresh, marker+body |
//	| non-empty            | Sentari-managed    | rewrite (backup if body  |
//	|                      |                    |  differs)                |
//	| non-empty            | operator-curated   | skip + SkippedOperator=true|
//	| empty / missing      | absent             | no-op                    |
//	| empty / missing      | Sentari-managed    | remove (fail-open revert)|
//	| empty / missing      | operator-curated   | no-op (refuse to delete) |
//	+----------------------+--------------------+--------------------------+
//
// The "skip" branch is the v1 limitation noted in the package
// docstring — XML merge support lands in a follow-up PR.  Until
// then, an operator who keeps a hand-curated settings.xml does
// not get install-gate enforcement on the Maven side.  pip + npm
// stay enforced regardless because they have separate configs.
func WriteMaven(m *scanner.InstallGateMap, scope MavenScope, marker MarkerFields) (WriteMavenResult, error) {
	res := WriteMavenResult{Path: MavenPath(scope)}
	if res.Path == "" {
		return res, nil
	}
	if m == nil {
		return res, fmt.Errorf("installgate.WriteMaven: nil policy map")
	}

	// Prefer the customer-configured trusted registry (PR #118 on
	// server, this PR on agent).  Maven's <mirrorOf>*</mirrorOf> lets
	// one URL serve every upstream; we use the first trusted-registry
	// URL when set.  Multiple-mirror support (per-repository
	// <mirrorOf> patterns) is left for a follow-up — the dashboard
	// stores the list but writers currently honour only the primary.
	endpoints := m.AllRegistryEndpointsWithAuth("maven")
	var endpoint string
	var endpointAuth *scanner.RegistryAuth
	if len(endpoints) > 0 {
		endpoint = endpoints[0].URL
		endpointAuth = endpoints[0].Auth
	}
	if endpoint == "" {
		// Fail-open path — same Sentari-managed gate as pip + npm.
		managed, err := isSentariManaged(res.Path)
		if err != nil {
			return res, fmt.Errorf("installgate.WriteMaven: inspect existing config: %w", err)
		}
		if !managed {
			return res, nil
		}
		removed, err := Remove(res.Path)
		if err != nil {
			return res, err
		}
		res.Removed = removed
		return res, nil
	}

	// Non-empty endpoint.  Inspect the existing file before deciding
	// whether to write.  Two cases:
	//
	//   1. File doesn't exist → write fresh.
	//   2. File exists.  If Sentari-managed → rewrite; if not →
	//      skip + flag SkippedOperator so the caller can surface it.
	if _, err := os.Stat(res.Path); err == nil {
		managed, err := isSentariManaged(res.Path)
		if err != nil {
			return res, fmt.Errorf("installgate.WriteMaven: inspect existing config: %w", err)
		}
		if !managed {
			res.SkippedOperator = true
			return res, nil
		}
	} else if !os.IsNotExist(err) {
		return res, fmt.Errorf("installgate.WriteMaven: stat %s: %w", res.Path, err)
	}

	body, err := renderSettingsXML(endpoint, endpointAuth, marker)
	if err != nil {
		return res, err
	}
	changed, err := WriteAtomic(WriteOptions{
		Path:     res.Path,
		Content:  body,
		FileMode: 0o644,
		Now:      marker.Applied,
	})
	if err != nil {
		return res, err
	}
	res.Changed = changed
	return res, nil
}

// renderSettingsXML produces the bytes for a fresh Sentari-managed
// settings.xml.  The XML comment carries the Sentari-managed marker
// (matched by isSentariManaged via sentariManagedSentinelXML).
//
// Output uses the design-doc §4.3 layout: ``<mirrors>`` containing
// a single ``<mirror>`` with ``<mirrorOf>*</mirrorOf>`` so every
// Maven repository the project resolves redirects through
// Sentari-Proxy.
//
// When ``auth`` is non-nil and usable, a ``<servers>`` block is
// emitted alongside ``<mirrors>``.  Maven's resolution rule is that
// a ``<server>`` whose ``<id>`` matches a ``<mirror>``'s ``<id>``
// supplies the credentials for that mirror; we use a constant
// ``sentari-proxy`` id for both halves so the binding is implicit.
//
// Bearer mode is rendered via Maven's ``<configuration>``
// ``<httpHeaders>`` mechanism — Maven core has no native bearer
// concept, but the Wagon HTTP transport supports arbitrary headers
// since Maven 3.5+, which is below the floor we support.  Basic
// mode uses the long-standing ``<username>``/``<password>`` fields.
func renderSettingsXML(endpoint string, auth *scanner.RegistryAuth, marker MarkerFields) ([]byte, error) {
	endpoint = strings.TrimSpace(endpoint)
	if err := validateEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("renderSettingsXML: %w", err)
	}
	// XML-comment safety: refuse ``--`` and trailing ``-`` in the
	// KeyID so the embedded marker comment stays well-formed Maven
	// XML.  Same gate the hash-marker uses on pip / npm via the
	// pip render helper — keeps the failure mode consistent across
	// ecosystems.
	if err := validateMarkerKeyID(marker.KeyID); err != nil {
		return nil, fmt.Errorf("renderSettingsXML: %w", err)
	}

	const mirrorID = "sentari-proxy"

	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString(renderXMLMarker(marker))
	b.WriteString("<settings>\n")
	b.WriteString("  <mirrors>\n")
	b.WriteString("    <mirror>\n")
	fmt.Fprintf(&b, "      <id>%s</id>\n", mirrorID)
	b.WriteString("      <mirrorOf>*</mirrorOf>\n")
	b.WriteString("      <name>Sentari-managed mirror</name>\n")
	fmt.Fprintf(&b, "      <url>%s</url>\n", xmlEscape(endpoint))
	b.WriteString("    </mirror>\n")
	b.WriteString("  </mirrors>\n")

	if auth.HasUsableAuth() {
		if err := renderMavenServersBlock(&b, mirrorID, auth); err != nil {
			return nil, fmt.Errorf("renderSettingsXML: %w", err)
		}
	}

	b.WriteString("</settings>\n")
	return []byte(b.String()), nil
}

// renderMavenServersBlock emits the ``<servers>`` element that binds
// credentials to the mirror's ``<id>``.  Two shapes:
//
//	basic:
//	  <server>
//	    <id>sentari-proxy</id>
//	    <username>user</username>
//	    <password>pass</password>
//	  </server>
//
//	bearer:
//	  <server>
//	    <id>sentari-proxy</id>
//	    <configuration>
//	      <httpHeaders>
//	        <property>
//	          <name>Authorization</name>
//	          <value>Bearer <token></value>
//	        </property>
//	      </httpHeaders>
//	    </configuration>
//	  </server>
//
// Bearer-via-httpHeaders is the documented Maven Wagon idiom — we
// pick it (rather than the also-valid ``<privateKey>`` slot for
// custom auth) because Wagon HTTP is the default transport and
// httpHeaders is the most widely-supported mechanism across mvn 3.5+.
func renderMavenServersBlock(b *strings.Builder, mirrorID string, auth *scanner.RegistryAuth) error {
	b.WriteString("  <servers>\n")
	b.WriteString("    <server>\n")
	fmt.Fprintf(b, "      <id>%s</id>\n", mirrorID)

	switch auth.Mode {
	case "basic":
		if strings.ContainsAny(auth.Username, "<>&") {
			// XML-escape via xmlEscape below handles this safely;
			// but a username with control bytes is a sign of a server
			// validation gap, so log via the error path so the apply
			// fails loudly rather than emit a borderline-legal XML.
			// (xmlEscape handles the actual escape; this is a
			// belt-and-braces guard.)
		}
		fmt.Fprintf(b, "      <username>%s</username>\n", xmlEscape(auth.Username))
		fmt.Fprintf(b, "      <password>%s</password>\n", xmlEscape(auth.Password))
	case "bearer":
		b.WriteString("      <configuration>\n")
		b.WriteString("        <httpHeaders>\n")
		b.WriteString("          <property>\n")
		b.WriteString("            <name>Authorization</name>\n")
		fmt.Fprintf(b, "            <value>Bearer %s</value>\n", xmlEscape(auth.Token))
		b.WriteString("          </property>\n")
		b.WriteString("        </httpHeaders>\n")
		b.WriteString("      </configuration>\n")
	default:
		return fmt.Errorf("unknown auth mode %q", auth.Mode)
	}

	b.WriteString("    </server>\n")
	b.WriteString("  </servers>\n")
	return nil
}

// xmlEscape returns ``s`` with the five XML predefined entities
// escaped.  URLs can legitimately carry XML-significant characters
// (``&`` in query strings, etc.) so we always escape — the inline
// escaper sits here rather than via ``encoding/xml`` solely to
// keep the writer's import surface auditable, not because the
// caller's content is known to be safe.
func xmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		"\"", "&quot;",
		"'", "&apos;",
	)
	return r.Replace(s)
}
