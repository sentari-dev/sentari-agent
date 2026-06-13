// npm / Node.js writer.
//
// Second ecosystem after pip.  ``.npmrc`` is structurally the
// simplest of the supported configs — flat ``key=value`` without
// section headers, no ``trusted-host`` equivalent (npm trusts any
// host whose TLS chain validates), and no port-stripping
// considerations (npm honours ports in registry URLs natively).
//
// Scope (design doc §4.2):
//
//   - Honours ``proxy_endpoints["npm"]`` from the policy-map.
//   - Writes only the top-level ``registry=`` setting.  Scoped-
//     registry mappings (``@vendor:registry=...``) are explicitly
//     deferred until a customer asks — the policy-map shape would
//     need a per-scope sub-field that doesn't exist yet.
//   - User scope (``~/.npmrc``) on Linux/macOS/Windows is the
//     dev-laptop default; system scope (``/etc/npmrc``) lands on
//     server hosts.  npm's per-project ``.npmrc`` overrides both
//     and we deliberately do NOT walk repos to write project-local
//     files (would be racy with repo creation + clone).

package installgate

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// NpmScope picks ``user`` or ``system`` ``.npmrc``.  Same defaulting
// story as ``PipScope``: zero-value → user (laptop default).
type NpmScope int

const (
	// NpmScopeUser writes ``~/.npmrc`` on every supported OS.
	NpmScopeUser NpmScope = iota

	// NpmScopeSystem writes ``/etc/npmrc`` on Linux/macOS.  npm's
	// "system"-level config on Windows is install-prefix-relative
	// (``${prefix}\etc\npmrc``) and the prefix moves around per
	// install method (msi / chocolatey / nvm-windows); ``NpmPath``
	// returns empty on Windows for system scope and the writer
	// becomes a soft no-op rather than guessing wrong.
	NpmScopeSystem
)

// NpmPath returns the absolute ``.npmrc`` path for the given scope
// on the running OS.  Empty return signals "skip" — the caller
// short-circuits to a soft no-op the same way ``WritePip`` does
// for un-derivable paths.
func NpmPath(scope NpmScope) string {
	switch scope {
	case NpmScopeUser:
		// npm uses ``$HOME/.npmrc`` uniformly.  On Windows
		// ``os.UserHomeDir`` consults USERPROFILE, which is what
		// npm itself reads.
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return ""
		}
		return filepath.Join(home, ".npmrc")
	case NpmScopeSystem:
		switch runtime.GOOS {
		case "windows":
			// npm's Windows "global" prefix is non-stable across
			// install methods; refuse rather than write to a path
			// npm won't read.  Operators on Windows should use
			// user-scope.
			return ""
		default:
			return "/etc/npmrc"
		}
	}
	return ""
}

// WriteNpmResult mirrors ``WritePipResult`` — same shape so the
// orchestrator log emits structurally-identical lines per
// ecosystem.
type WriteNpmResult struct {
	Path    string
	Changed bool
	Removed bool
}

// WriteNpm applies the npm section of a verified policy-map to
// the host.  Behaviour matrix matches ``WritePip``:
//
//	+----------------------+--------------------+--------------------------+
//	| proxy_endpoints[npm] | existing           | action                   |
//	+----------------------+--------------------+--------------------------+
//	| non-empty            | absent             | write fresh, marker+body |
//	| non-empty            | present            | rewrite (backup if body  |
//	|                      |                    |  differs)                |
//	| empty / missing      | absent             | no-op                    |
//	| empty / missing      | Sentari-managed    | remove (fail-open revert)|
//	| empty / missing      | operator-curated   | no-op (refuse to delete) |
//	+----------------------+--------------------+--------------------------+
//
// The Sentari-managed gate on the fail-open ``remove`` branch is
// the same as pip's: an operator-curated ``.npmrc`` (auth tokens
// for private registries, custom cache locations) MUST survive
// install-gate disablement intact.
func WriteNpm(m *scanner.InstallGateMap, scope NpmScope, marker MarkerFields) (WriteNpmResult, error) {
	res := WriteNpmResult{Path: NpmPath(scope)}
	if res.Path == "" {
		// Soft no-op — orchestrator logs and moves on.
		return res, nil
	}
	if m == nil {
		return res, fmt.Errorf("installgate.WriteNpm: nil policy map")
	}

	// Prefer the customer-configured trusted registry (post-PR-#118
	// on the server) over Sentari-Proxy.  npm supports per-scope
	// registries too, but a per-tenant 'use my Nexus everywhere'
	// override applies to the root ``registry=`` line — additional
	// trusted registries beyond the first are out of scope for the
	// .npmrc shape (npm only resolves one root registry; multi-
	// registry workflows use scope mappings the operator declares
	// outside this writer).
	endpoints := m.AllRegistryEndpointsWithAuth("npm")
	var endpoint string
	var endpointAuth *scanner.RegistryAuth
	if len(endpoints) > 0 {
		endpoint = endpoints[0].URL
		endpointAuth = endpoints[0].Auth
	}
	if endpoint == "" {
		managed, err := isSentariManaged(res.Path)
		if err != nil {
			return res, fmt.Errorf("installgate.WriteNpm: inspect existing config: %w", err)
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

	// Read any existing .npmrc so we MERGE rather than clobber.  Unlike
	// pip.conf (a complete Sentari override), .npmrc commonly carries
	// the operator's ``_authToken`` lines, scoped-registry mappings and
	// cache settings; replacing the whole file would silently strip
	// those from the ACTIVE config (a backup alone doesn't help — npm
	// reads the live file).  We splice our registry into a delimited
	// Sentari block and preserve every other line verbatim.  safeio
	// refuses a symlinked path (handled by readBoundedIfExists).
	existing, err := readBoundedIfExists(res.Path)
	if err != nil {
		return res, fmt.Errorf("installgate.WriteNpm: inspect existing config: %w", err)
	}

	body, err := renderNpmrcMerged(existing, endpoint, endpointAuth, marker)
	if err != nil {
		return res, err
	}

	// 0o600: the .npmrc can carry ``_authToken`` / ``_auth``
	// credential lines, so it gets the same owner-only mode as the
	// pip netrc (policy-map contract: credential-bearing files MUST
	// be 0600).  WriteAtomic chmods the temp file before the rename,
	// so a pre-existing world-readable file is tightened on rewrite.
	changed, err := WriteAtomic(WriteOptions{
		Path:     res.Path,
		Content:  body,
		FileMode: 0o600,
		Now:      marker.Applied,
	})
	if err != nil {
		return res, err
	}
	res.Changed = changed
	return res, nil
}

// npmBlockStart / npmBlockEnd delimit the Sentari-managed region
// inside an .npmrc.  Everything between (and including) these two
// lines is owned by the writer and replaced on every apply; every
// other line in the file is operator-curated and preserved verbatim.
// The start line carries the ``# Managed by Sentari`` substring so
// isSentariManaged still recognises a merged file as managed.
const (
	npmBlockStart = "# >>> Sentari-managed block — do not edit inside this block. Managed by Sentari >>>"
	npmBlockEnd   = "# <<< Sentari-managed block <<<"
)

// renderNpmrcMerged produces the bytes for an .npmrc that splices the
// Sentari registry into a delimited managed block while PRESERVING
// every operator-curated line (auth tokens, scoped registries, cache
// settings) outside that block.
//
// Why merge instead of replace: npm reads the live .npmrc, and that
// file commonly holds ``//host/:_authToken=`` lines an operator needs
// for private-registry auth.  A full overwrite (pip-style) would drop
// those from the ACTIVE file; a side backup doesn't restore live auth.
//
// Strategy: strip any prior Sentari block from ``existing`` (idempotent
// re-apply replaces the block in place), keep all other lines verbatim,
// then append a freshly-rendered block at the end.  npm's last-wins
// duplicate-key semantics mean our trailing ``registry=`` overrides any
// operator ``registry=`` earlier in the file — enforcement holds while
// the operator's other settings survive.
func renderNpmrcMerged(existing []byte, endpoint string, auth *scanner.RegistryAuth, marker MarkerFields) ([]byte, error) {
	endpoint = strings.TrimSpace(endpoint)
	if err := validateEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("renderNpmrcMerged: %w", err)
	}
	if err := validateMarkerKeyID(marker.KeyID); err != nil {
		return nil, fmt.Errorf("renderNpmrcMerged: %w", err)
	}
	// npm's registry URL must end with ``/`` — npm appends paths
	// directly to it without inserting a separator, so a missing
	// trailing slash silently breaks tarball lookups.  Add one if
	// the operator forgot.
	if !strings.HasSuffix(endpoint, "/") {
		endpoint += "/"
	}

	preserved := stripSentariBlock(existing)

	var b strings.Builder
	// Preserved operator lines first (verbatim), then our block last so
	// last-wins resolves the registry in our favour.
	if len(preserved) > 0 {
		b.Write(preserved)
		if preserved[len(preserved)-1] != '\n' {
			b.WriteByte('\n')
		}
	}
	b.WriteString(npmBlockStart)
	b.WriteString("\n")
	b.WriteString(renderHashMarker(marker))
	fmt.Fprintf(&b, "registry=%s\n", endpoint)

	// Auth lines, when configured.  npm's authentication directives are
	// keyed by the **registry URL without scheme**, with a leading
	// ``//`` — e.g. ``//nexus.acme.com/repository/npm/:_authToken=...``.
	// We derive that key once and use it for every auth directive so
	// bearer / basic both bind to the exact endpoint we just wrote on
	// the registry= line; a mismatch (host typo, trailing-slash drift)
	// silently breaks auth at install time.
	if auth.HasUsableAuth() {
		if err := renderNpmAuthLines(&b, endpoint, auth); err != nil {
			return nil, fmt.Errorf("renderNpmrcMerged: %w", err)
		}
	}

	b.WriteString(npmBlockEnd)
	b.WriteString("\n")
	return []byte(b.String()), nil
}

// renderNpmAuthLines emits npm's per-registry auth directives.  Two
// shapes supported:
//
//	bearer:  //host/path/:_authToken=<token>
//	         //host/path/:always-auth=true
//	basic:   //host/path/:_auth=<base64(user:password)>
//	         //host/path/:always-auth=true
//
// The ``always-auth=true`` line forces npm to send credentials on
// every request (including tarball downloads) — without it, npm only
// authenticates the metadata request and tarball fetches go
// anonymous, which fails on a 401-requiring Nexus.
//
// Credential validation (no whitespace / control chars in the values)
// is enforced server-side; this function adds a defensive guard that
// returns an error rather than emit a malformed .npmrc line — better
// to fail the apply than write a half-broken file that npm rejects.
func renderNpmAuthLines(b *strings.Builder, endpoint string, auth *scanner.RegistryAuth) error {
	prefix, err := npmAuthKeyPrefix(endpoint)
	if err != nil {
		return err
	}
	switch auth.Mode {
	case "bearer":
		if strings.ContainsAny(auth.Token, " \t\r\n") {
			return fmt.Errorf("bearer token contains whitespace")
		}
		fmt.Fprintf(b, "%s:_authToken=%s\n", prefix, auth.Token)
		fmt.Fprintf(b, "%s:always-auth=true\n", prefix)
	case "basic":
		if strings.ContainsAny(auth.Username, " \t\r\n:") {
			return fmt.Errorf("basic username contains whitespace or colon")
		}
		if strings.ContainsAny(auth.Password, "\r\n") {
			return fmt.Errorf("basic password contains line terminator")
		}
		encoded := base64.StdEncoding.EncodeToString([]byte(auth.Username + ":" + auth.Password))
		fmt.Fprintf(b, "%s:_auth=%s\n", prefix, encoded)
		fmt.Fprintf(b, "%s:always-auth=true\n", prefix)
	default:
		// Unknown mode — caller's HasUsableAuth check should have
		// gated this out.  Defence-in-depth: return error.
		return fmt.Errorf("unknown auth mode %q", auth.Mode)
	}
	return nil
}

// npmAuthKeyPrefix converts a registry URL into the ``//host/path/``
// form npm uses to key auth directives.  Strips the scheme, keeps
// host + port + path with a guaranteed trailing slash.
func npmAuthKeyPrefix(endpoint string) (string, error) {
	rest := endpoint
	for _, scheme := range []string{"https://", "http://"} {
		if strings.HasPrefix(rest, scheme) {
			rest = rest[len(scheme):]
			break
		}
	}
	if rest == "" {
		return "", fmt.Errorf("endpoint %q has no host", endpoint)
	}
	if !strings.HasSuffix(rest, "/") {
		rest += "/"
	}
	return "//" + rest, nil
}

// stripSentariBlock returns ``content`` with any single Sentari-managed
// block (the lines from npmBlockStart through npmBlockEnd, inclusive)
// removed.  Used so an idempotent re-apply replaces the block in place
// rather than stacking a second one.  If no block is present the input
// is returned unchanged.  A start without a matching end is treated as
// "block runs to EOF" — conservative: we never leave a half-block that
// could confuse the next parse.
func stripSentariBlock(content []byte) []byte {
	if len(content) == 0 {
		return nil
	}
	lines := strings.Split(string(content), "\n")
	var out []string
	inBlock := false
	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		if !inBlock && trimmed == npmBlockStart {
			inBlock = true
			continue
		}
		if inBlock {
			if trimmed == npmBlockEnd {
				inBlock = false
			}
			continue
		}
		out = append(out, line)
	}
	joined := strings.Join(out, "\n")
	// Drop a trailing empty element produced by Split when the input
	// ended in a newline, so we don't accumulate blank lines on repeat
	// merges.
	joined = strings.TrimRight(joined, "\n")
	if joined == "" {
		return nil
	}
	return []byte(joined)
}
