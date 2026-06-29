// Pip / Python writer.
//
// The first ecosystem writer in Phase B.  pip.conf is the simplest
// of the supported ecosystems (one INI file, two settings) so it
// proves the end-to-end flow — cached signed envelope → rendered
// native config → blocked install — before we tackle Maven's XML
// merging, NuGet's package-source-clearing dance, or apt's GPG-
// keyring drop-ins.
//
// Scope:
//
//   - Honours ``proxy_endpoints["pypi"]`` from the policy-map.  An
//     empty endpoint is a no-op (Phase-A deployments where the
//     server has policies but no proxy URL configured).
//   - Writes both index-url and trusted-host (pip refuses to talk
//     to a non-PyPI HTTPS host without ``trusted-host`` even when
//     the cert chains to a system-trusted CA).
//   - Writes only the system-or-user config; never touches
//     virtualenv-local pip.conf because (a) walking every venv on
//     a host is racy with venv creation and (b) system/user config
//     applies regardless unless the venv explicitly overrides.

package installgate

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// PipScope is the precedence target for pip.conf.  ``user`` is the
// dev-laptop default; ``system`` is the server-host default.  The
// agent's config picks one — there's no "both" mode (pip's own
// precedence rules would resolve them, but writing two files
// doubles the audit surface for no real benefit).
type PipScope int

const (
	// PipScopeUser writes the per-user pip config:
	// ``~/.config/pip/pip.conf`` on Linux/macOS,
	// ``%APPDATA%\pip\pip.ini`` on Windows.
	PipScopeUser PipScope = iota

	// PipScopeSystem writes the system-wide pip config:
	// ``/etc/pip.conf`` on Linux/macOS, ``%ProgramData%\pip\pip.ini``
	// on Windows.
	PipScopeSystem
)

// PipPath returns the absolute pip-config path for the given scope
// on the running OS.  Returns an empty string when the path can't
// be derived (no ``HOME`` env var on Linux user-scope, no
// ``APPDATA`` env var on Windows).  Callers treat the empty case
// as "skip pip writer for this scope" and emit a typed warning.
func PipPath(scope PipScope) string {
	switch runtime.GOOS {
	case "windows":
		switch scope {
		case PipScopeUser:
			if dir := os.Getenv("APPDATA"); dir != "" {
				return filepath.Join(dir, "pip", "pip.ini")
			}
			return ""
		case PipScopeSystem:
			if dir := os.Getenv("ProgramData"); dir != "" {
				return filepath.Join(dir, "pip", "pip.ini")
			}
			// Hard-coded fallback: %ProgramData% defaults to
			// C:\ProgramData on every supported Windows version.
			return `C:\ProgramData\pip\pip.ini`
		}
	default: // linux, darwin, freebsd, …
		switch scope {
		case PipScopeUser:
			// XDG_CONFIG_HOME first, then ~/.config — same precedence
			// pip itself uses internally, so the writer ends up at
			// the same path pip will read from.
			if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
				return filepath.Join(xdg, "pip", "pip.conf")
			}
			home, err := os.UserHomeDir()
			if err != nil || home == "" {
				return ""
			}
			return filepath.Join(home, ".config", "pip", "pip.conf")
		case PipScopeSystem:
			return "/etc/pip.conf"
		}
	}
	return ""
}

// WritePipResult describes the outcome of one pip writer run.
// Returned per scope so the orchestrator can log a precise summary
// (e.g. "rewrote /etc/pip.conf, no change to ~/.config/pip/pip.conf").
type WritePipResult struct {
	// Path is the resolved final destination, or empty if the path
	// could not be derived for the running OS.
	Path string

	// Changed is true iff the file was created or its contents
	// differ from what was already there.  ``false`` covers both
	// the no-op case (idempotent re-write) and the no-policy-no-
	// proxy case (writer produced no file).
	Changed bool

	// Removed is true iff the writer removed an existing
	// Sentari-managed config (fail-open path: the policy-map no
	// longer points pip anywhere, so the agent should revert).
	Removed bool

	// ReplacedOperator is true iff the writer overwrote an existing
	// operator-curated pip.conf (a file present WITHOUT the Sentari
	// marker).  pip.conf is a complete Sentari override — we do not
	// merge — so the operator's prior settings survive only in the
	// ``.sentari-backup-*`` the writer always creates on this path.
	// The orchestrator surfaces this flag to the audit log so the
	// replacement is never a silent clobber.
	ReplacedOperator bool

	// NetrcPath is the resolved ``~/.netrc`` destination (or empty
	// when no home directory could be resolved on this host).
	// Per-registry credentials are applied via ``.netrc`` — pip /
	// pipenv / poetry / uv all consult it natively, and it keeps the
	// credential string out of ``pip config list`` (which would dump
	// the URL of a URL-embedded credential).  The Sentari-managed
	// section is delimited by sentinel lines so operator records
	// outside our block survive verbatim.
	NetrcPath string

	// NetrcChanged is true iff the writer created the file or its
	// contents differ from what was there.
	NetrcChanged bool

	// NetrcRemoved is true iff the policy-map carries no credentialed
	// registries any more and the writer dropped the Sentari-managed
	// section from an existing ``.netrc`` (preserving operator records
	// outside the section).  The whole file is removed only when the
	// preserved content is empty.
	NetrcRemoved bool

	// NetrcTeardownFailed is true iff the fail-open path attempted to
	// strip / remove the Sentari-managed netrc section and that
	// teardown failed.  pip.conf removal still succeeded (fail-open
	// honours the operator's primary intent) but a credentialed netrc
	// may remain on disk; the writer logs it and the orchestrator can
	// surface it to the audit log.  False on the happy path and on
	// every non-fail-open path.
	NetrcTeardownFailed bool
}

// applyPipNetrcFn is the seam through which WritePip applies the netrc
// companion.  It defaults to ``applyPipNetrc`` and exists as a package
// var ONLY so tests can inject a failing teardown to exercise the
// fail-open visibility path (a leftover credentialed netrc must never
// be silently swallowed).  Production code never reassigns it.
var applyPipNetrcFn = applyPipNetrc

// WritePip applies the pip section of a verified policy-map to the
// host.  Returns the resolved path + whether the file changed.
//
// Behaviour matrix:
//
//	+----------------------+--------------------+--------------------------+
//	| proxy_endpoints[pypi]| existing           | action                   |
//	+----------------------+--------------------+--------------------------+
//	| non-empty            | absent             | write fresh, marker+body |
//	| non-empty            | present            | rewrite (backup if body  |
//	|                      |                    |  differs)                |
//	| empty / missing      | absent             | no-op                    |
//	| empty / missing      | Sentari-managed    | remove (fail-open revert)|
//	| empty / missing      | operator-curated   | no-op (refuse to delete) |
//	+----------------------+--------------------+--------------------------+
//
// The fail-open ``remove`` branch is gated on the existing file
// carrying the Sentari marker — we never delete an operator-curated
// pip.conf that pre-dated install-gate enrolment, even if the
// policy-map drops the proxy URL.  Any pre-existing content on a
// host's first install-gate apply has already been preserved at
// ``<path>.sentari-backup-<timestamp>``; a Sentari-managed file is
// the only state we own and the only thing we'll remove.
//
// When ``PipPath`` cannot derive a target (no ``HOME`` on Linux
// user-scope, no ``APPDATA`` on Windows), the call is a soft no-op:
// returns ``(res, nil)`` with empty ``Path``.  The orchestrator
// inspects the result and logs a warning — a hard error here would
// crash the agent on a misconfigured host where pip simply isn't
// installed.
func WritePip(m *scanner.InstallGateMap, scope PipScope, marker MarkerFields) (WritePipResult, error) {
	res := WritePipResult{Path: PipPath(scope)}
	if res.Path == "" {
		// Soft no-op — the orchestrator logs and moves on.
		return res, nil
	}
	if m == nil {
		return res, fmt.Errorf("installgate.WritePip: nil policy map")
	}

	// Prefer a customer-configured trusted registry (post-PR-#118 on
	// the server, post-this-PR on the agent) over Sentari-Proxy.  pip
	// has native support for index-url + extra-index-url, so the
	// primary URL becomes index-url and any additional trusted
	// registries are appended as extra-index-url entries.
	endpoints := m.AllRegistryEndpoints("pypi")
	var endpoint string
	if len(endpoints) > 0 {
		endpoint = endpoints[0]
	}
	if endpoint == "" {
		// Fail-open: no proxy configured for pypi.  Remove only if
		// the existing file is Sentari-managed; never touch an
		// operator-curated pip.conf.  ``isSentariManaged`` returns
		// false for absent files, so a host that never had pip
		// configured stays inert.
		managed, err := isSentariManaged(res.Path)
		if err != nil {
			return res, fmt.Errorf("installgate.WritePip: inspect existing config: %w", err)
		}
		if !managed {
			return res, nil
		}
		removed, err := Remove(res.Path)
		if err != nil {
			return res, err
		}
		res.Removed = removed

		// Symmetric tear-down on the netrc side: an empty policy is
		// telling us "do nothing for pypi", so the Sentari-managed
		// credential block must also go.  Pass an effectively empty
		// map so applyPipNetrc strips its sentinel block from any
		// pre-existing ``.netrc`` while preserving operator records
		// outside it.  Errors here are non-fatal — pip.conf is gone,
		// the operator's main intent is honoured.
		//
		// When the prior netrc had operator records + a Sentari
		// block, the rewrite path produces ``changed=true`` AND
		// ``removed=true`` (block dropped, file rewritten); we
		// surface both flags so an audit-log consumer reading
		// NetrcChanged still sees the rewrite — Copilot, PR #45.
		//
		// A teardown failure here is NOT swallowed: a leftover
		// Sentari-managed ``.netrc`` keeps credentials live on disk
		// after the policy told us to revert, which is a credential-
		// exposure concern.  pip.conf has already been removed (the
		// operator's primary intent is honoured) so we keep the
		// fail-open contract and do not turn this into a hard error,
		// but the failure MUST be visible: we log it at the writer
		// level and surface NetrcTeardownFailed on the result so the
		// orchestrator can record it in the audit log.
		path, changed, dropped, nerr := applyPipNetrcFn(m, marker)
		res.NetrcPath = path
		if nerr != nil {
			res.NetrcTeardownFailed = true
			log.Printf("[installgate] pip fail-open: netrc teardown failed for %s: %v "+
				"(credentialed netrc may still be present on disk)", path, nerr)
		} else {
			res.NetrcChanged = changed
			res.NetrcRemoved = dropped
		}
		return res, nil
	}

	// Auditability: detect whether we are about to overwrite an
	// operator-curated config (present but lacking the Sentari marker)
	// BEFORE WriteAtomic backs it up and replaces it.  isSentariManaged
	// returns (false, nil) for absent files and for marker-less files;
	// we distinguish the two with an explicit existence check so a
	// fresh write doesn't false-flag.  Routed through safeio inside
	// isSentariManaged, so a symlinked path errors out here too.
	managed, err := isSentariManaged(res.Path)
	if err != nil {
		return res, fmt.Errorf("installgate.WritePip: inspect existing config: %w", err)
	}
	replacingOperator := false
	if !managed {
		if _, statErr := os.Lstat(res.Path); statErr == nil {
			// File exists but carries no Sentari marker → operator-curated.
			replacingOperator = true
		}
	}

	// extras = everything after the primary URL; rendered as
	// extra-index-url lines per the pip docs.
	extras := endpoints[1:]
	body, err := renderPipConf(endpoint, extras, marker)
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
	// Only flag when we actually replaced content (Changed) — a no-op
	// idempotent re-write of an identical file shouldn't claim a
	// replacement.  WriteAtomic guarantees the backup on the
	// content-differs path, so Changed && replacingOperator ⇒ backup
	// written.
	res.ReplacedOperator = changed && replacingOperator

	// Apply per-registry credentials via ``~/.netrc`` companion.
	// pip / pipenv / poetry / uv all read it natively; the credential
	// string never lands in ``pip.conf`` (where it would surface in
	// ``pip config list``).  See ``applyPipNetrc`` for failure modes
	// and the documented limitation around system-scope vs the
	// agent's home directory.
	netrcPath, netrcChanged, netrcRemoved, err := applyPipNetrc(m, marker)
	if err != nil {
		// pip.conf was already written; surface the netrc failure but
		// don't unwind the URL apply — partial application (URL applied,
		// credentials missing) surfaces as an auth failure against the
		// mirror, which is preferable to rolling back the URL and
		// reverting to public PyPI on a host where the operator wanted
		// the private mirror.
		return res, fmt.Errorf("installgate.WritePip: apply netrc: %w", err)
	}
	res.NetrcPath = netrcPath
	res.NetrcChanged = netrcChanged
	res.NetrcRemoved = netrcRemoved
	return res, nil
}

// renderPipConf produces the bytes for the rendered pip.conf.
// Format matches design doc §4.1 — the marker block, then the
// ``[global]`` section with ``index-url`` and ``trusted-host``.
//
// We do NOT attempt to merge with an operator-curated pip.conf:
// the file we write is a complete Sentari-managed override.  The
// backup created on first write preserves any prior operator
// config; an operator who wants to keep their settings can disable
// install-gate at the agent level, which removes our file and
// surfaces the backup as a candidate restore.
func renderPipConf(endpoint string, extras []string, marker MarkerFields) ([]byte, error) {
	// Defensive trim: a stray trailing newline in the proxy URL
	// from a hand-edited config would land mid-INI on the
	// ``index-url =`` line and break pip's parser.
	endpoint = strings.TrimSpace(endpoint)
	if err := validateEndpoint(endpoint); err != nil {
		return nil, fmt.Errorf("renderPipConf: %w", err)
	}
	if err := validateMarkerKeyID(marker.KeyID); err != nil {
		return nil, fmt.Errorf("renderPipConf: %w", err)
	}

	host, err := hostOf(endpoint)
	if err != nil {
		return nil, fmt.Errorf("renderPipConf: derive host from endpoint: %w", err)
	}

	// ``trusted-host`` DISABLES pip's TLS certificate verification for
	// the listed hosts — pip skips the cert chain AND the hostname
	// check for any host on this line.  Emitting it for an HTTPS index
	// is a silent security downgrade: a MITM with any cert (or none)
	// can impersonate the credential-bearing mirror.  We therefore
	// gate each host on the scheme of its endpoint and only ever trust
	// a host reached over plaintext ``http://`` — where there is no TLS
	// to verify in the first place, so ``trusted-host`` is pip's
	// required opt-in to talk to a plaintext index rather than a
	// downgrade.  The server only ever emits ``https://`` endpoints
	// (``_validate_url`` rejects ``http``), so in practice this line is
	// omitted entirely; the gate is defence-in-depth for a hand-edited
	// or future plaintext-mirror deployment.
	insecureHosts := []string{}
	if isInsecureScheme(endpoint) {
		insecureHosts = appendUniqueHost(insecureHosts, host)
	}

	// Validate each extra registry the same way as the primary so a
	// stray bad URL surfaces before we write the file rather than at
	// pip's first install attempt.  Collect the plaintext extras' hosts
	// for the single trusted-host line we may emit below.
	cleaned := make([]string, 0, len(extras))
	seen := map[string]struct{}{endpoint: {}}
	for _, e := range extras {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, dup := seen[e]; dup {
			continue
		}
		if err := validateEndpoint(e); err != nil {
			return nil, fmt.Errorf("renderPipConf: extra endpoint %q: %w", e, err)
		}
		eh, err := hostOf(e)
		if err != nil {
			return nil, fmt.Errorf("renderPipConf: derive host from extra %q: %w", e, err)
		}
		seen[e] = struct{}{}
		cleaned = append(cleaned, e)
		if isInsecureScheme(e) {
			insecureHosts = appendUniqueHost(insecureHosts, eh)
		}
	}

	var b strings.Builder
	b.WriteString(renderHashMarker(marker))
	b.WriteString("[global]\n")
	fmt.Fprintf(&b, "index-url = %s\n", endpoint)
	if len(cleaned) > 0 {
		// pip's [global] section is parsed by Python's configparser,
		// which rejects duplicate option names with a
		// ``DuplicateOptionError``.  ``extra-index-url`` must therefore
		// be a *single* option whose value is the whitespace-separated
		// list of URLs — pip then splits on whitespace at install
		// time.  (Initial-PR-#44 emitted one ``extra-index-url`` line
		// per URL, which configparser would refuse before pip even
		// saw it — Copilot flag.)
		fmt.Fprintf(&b, "extra-index-url = %s\n", strings.Join(cleaned, " "))
	}
	// Only emit the line at all when at least one plaintext host needs
	// it — an HTTPS-only config (the common case) keeps full TLS
	// verification with no ``trusted-host`` line present.
	if len(insecureHosts) > 0 {
		fmt.Fprintf(&b, "trusted-host = %s\n", strings.Join(insecureHosts, " "))
	}
	return []byte(b.String()), nil
}

// isInsecureScheme reports whether an endpoint URL is reached over
// plaintext ``http://``.  Used to gate the pip ``trusted-host`` line —
// see the comment in ``renderPipConf``.  Comparison is case-insensitive
// on the scheme because URL schemes are case-insensitive (RFC 3986
// §3.1) and a hand-edited ``HTTP://`` must not slip past the gate.
func isInsecureScheme(endpoint string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(endpoint)), "http://")
}

func appendUniqueHost(hosts []string, h string) []string {
	for _, existing := range hosts {
		if existing == h {
			return hosts
		}
	}
	return append(hosts, h)
}

// hostOf returns the bare host (no scheme, no port) of an endpoint
// URL.  Used for the ``trusted-host`` line.  Implemented
// without importing ``net/url`` because the parsing is trivial and
// we want stable error messages — net/url's errors include the
// full URL on failure, which would land in operator log files
// alongside whatever configuration secret happens to be embedded.
func hostOf(endpoint string) (string, error) {
	rest := endpoint
	// URL schemes are case-insensitive (RFC 3986 §3.1); strip the
	// scheme regardless of case so a hand-edited ``HTTP://`` resolves
	// the same bare host as ``http://`` (and matches isInsecureScheme,
	// which is likewise case-insensitive).
	lower := strings.ToLower(rest)
	for _, scheme := range []string{"https://", "http://"} {
		if strings.HasPrefix(lower, scheme) {
			rest = rest[len(scheme):]
			break
		}
	}
	// Trim path / query.
	if i := strings.IndexAny(rest, "/?#"); i != -1 {
		rest = rest[:i]
	}
	// Trim port.  pip's ``trusted-host`` does NOT accept a port —
	// providing host:port silently downgrades to plain host but
	// emits a warning, which we'd rather avoid.
	if i := strings.LastIndex(rest, ":"); i != -1 {
		// Keep IPv6 literals (``[::1]:8080``) intact-up-to-port:
		// strip only when the remaining suffix is digits.
		port := rest[i+1:]
		if isAllDigits(port) {
			rest = rest[:i]
		}
	}
	if rest == "" {
		return "", fmt.Errorf("endpoint has no host component")
	}
	return rest, nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
