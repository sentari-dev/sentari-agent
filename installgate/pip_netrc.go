// Pip writer — ``~/.netrc`` credential applier.
//
// pip / pipenv / poetry / uv all read ``~/.netrc`` natively for
// HTTP basic authentication against the index server.  By writing
// per-registry credentials there instead of URL-embedding them in
// ``pip.conf`` we keep them out of ``pip config list`` output
// (which would otherwise echo the URL) and we keep the credential
// string out of the operator log that often captures ``pip install``
// invocations verbatim.
//
// Threat-model notes:
//
//   - The file is written 0o600 (owner-only read/write).  Any
//     credential leak from a stolen device is the netrc's scope, not
//     pip.conf's scope.
//   - The credential cleartext appears in the netrc by design.
//     Sentari does not have a way to push tokens to pip in a form
//     pip will use that isn't ultimately cleartext on disk —
//     industry-standard.  See the PR-B discussion in the contract
//     doc for the alternative architecture (Sentari-Proxy injects
//     ``Authorization`` headers; credentials never touch the
//     device).  Today's design ships per-device credentials.
//   - Merge-not-replace strategy: a Sentari-managed block lives
//     between two sentinel lines; everything outside is preserved.
//     Operator-curated ``machine github.com ...`` records survive
//     unchanged.
//
// System-scope limitation: there is no ``/etc/netrc`` that pip
// reads — pip resolves ``~/.netrc`` of the OS user invoking it.
// The writer always targets the agent's own ``$HOME/.netrc``.  When
// the agent runs as root (system pip scope) and `pip install` is
// invoked by a different user, that user does NOT see the
// credentials — they read their own ``$HOME/.netrc``.  Document this
// for multi-user hosts; for single-service-account hosts (the common
// install) it's fine.

package installgate

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// netrcBlockStart / netrcBlockEnd delimit the Sentari-managed region
// inside ``~/.netrc``.  Comment lines (``#`` prefix) are recognised
// by every netrc parser this writer cares about (Python's
// ``netrc`` stdlib, Go's libcurl-style parsers, libcurl itself, git).
const (
	netrcBlockStart = "# >>> Sentari-managed block — do not edit inside this block. Managed by Sentari >>>"
	netrcBlockEnd   = "# <<< Sentari-managed block <<<"
)

// PipNetrcPath returns the absolute path of the netrc file the pip
// writer will manage on this host.  Empty when no home directory can
// be resolved (caller treats as soft no-op, same convention as
// PipPath).
//
// Unlike ``PipPath`` this is **scope-independent** — pip's netrc
// lookup is per-OS-user, not per-system, so we always write to the
// agent's own ``$HOME/.netrc`` regardless of whether pip.conf went
// to ``~/.config/pip/pip.conf`` or ``/etc/pip.conf``.
func PipNetrcPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".netrc")
}

// applyPipNetrc renders + writes the Sentari-managed netrc section
// for every pypi trusted-registry entry that carries usable auth.
// Operator records outside the sentinel block are preserved.
//
// Returns ``(path, changed, removed, err)``:
//   - ``path``: the resolved netrc target (empty when soft no-op).
//   - ``changed``: file created or contents differ from prior state.
//   - ``removed``: the file was deleted entirely (no Sentari content
//     remained AND no preserved operator content remained).
//   - ``err``: hard failure (read/write/permission); soft failures
//     like "no home dir" / "no credentialed registries" return
//     ``(path, false, false, nil)``.
func applyPipNetrc(m *scanner.InstallGateMap, marker MarkerFields) (path string, changed bool, removed bool, err error) {
	path = PipNetrcPath()
	if path == "" {
		// No home → soft no-op.  Caller logs.
		return "", false, false, nil
	}

	// Collect the (host, auth) pairs we need to apply.  Sentari-Proxy
	// fallback URLs are intentionally skipped — proxy auth is
	// agent-side mTLS, not basic/bearer at the netrc layer.
	creds := collectPipCreds(m)

	existing, err := readBoundedIfExists(path)
	if err != nil {
		return path, false, false, fmt.Errorf("read existing netrc: %w", err)
	}

	preserved := stripNetrcSentariBlock(existing)

	// When there are no credentials to apply AND no operator content
	// was preserved, remove the file outright — Sentari created it,
	// Sentari owns the whole content, no longer needed.  When there
	// IS preserved operator content, drop only the Sentari block and
	// rewrite.
	if len(creds) == 0 {
		if len(preserved) == 0 {
			if existing == nil {
				// File never existed → nothing to do.
				return path, false, false, nil
			}
			// File existed but Sentari owned it all → remove.
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return path, false, false, fmt.Errorf("remove netrc: %w", err)
			}
			return path, false, true, nil
		}
		// Operator content remains; rewrite without the Sentari block.
		body := append([]byte(nil), preserved...)
		if len(body) > 0 && body[len(body)-1] != '\n' {
			body = append(body, '\n')
		}
		ch, werr := WriteAtomic(WriteOptions{
			Path:     path,
			Content:  body,
			FileMode: 0o600,
			Now:      marker.Applied,
		})
		if werr != nil {
			return path, false, false, fmt.Errorf("rewrite netrc without sentari block: %w", werr)
		}
		return path, ch, ch, nil
	}

	rendered, err := renderNetrcMerged(preserved, creds, marker)
	if err != nil {
		return path, false, false, fmt.Errorf("render netrc: %w", err)
	}
	ch, werr := WriteAtomic(WriteOptions{
		Path:     path,
		Content:  rendered,
		FileMode: 0o600,
		Now:      marker.Applied,
	})
	if werr != nil {
		return path, false, false, fmt.Errorf("write netrc: %w", werr)
	}
	return path, ch, false, nil
}

// pipNetrcCred is the resolved (host, login, password) tuple a single
// netrc ``machine`` record requires.  Bearer mode is rendered as a
// ``machine <host> login __token__ password <token>`` record per
// the GitLab / Artifactory bearer-via-netrc convention pip honours.
type pipNetrcCred struct {
	Host     string
	Login    string
	Password string
}

// collectPipCreds extracts the credentialed pypi mirrors from the
// envelope.  Order matches AllRegistryEndpointsWithAuth — operator-
// declared trusted registries first, then any Sentari-Proxy fallback
// (which never has auth attached server-side, so it's filtered out
// here).  Duplicate hosts are deduped on first-occurrence — pip's
// netrc lookup is first-match-wins, and a single host can only have
// one credential anyway.
func collectPipCreds(m *scanner.InstallGateMap) []pipNetrcCred {
	if m == nil {
		return nil
	}
	endpoints := m.AllRegistryEndpointsWithAuth("pypi")
	var out []pipNetrcCred
	seen := map[string]struct{}{}
	for _, ep := range endpoints {
		if !ep.Auth.HasUsableAuth() {
			continue
		}
		host, herr := netrcHostOf(ep.URL)
		if herr != nil {
			// Unparseable URL — applyPipNetrc has already passed
			// through renderPipConf which validates URLs, so this
			// branch is defensive: skip the entry rather than abort
			// the whole apply.
			continue
		}
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		switch ep.Auth.Mode {
		case "bearer":
			out = append(out, pipNetrcCred{
				Host:     host,
				Login:    "__token__",
				Password: ep.Auth.Token,
			})
		case "basic":
			out = append(out, pipNetrcCred{
				Host:     host,
				Login:    ep.Auth.Username,
				Password: ep.Auth.Password,
			})
		}
	}
	return out
}

// renderNetrcMerged produces the netrc bytes: preserved operator
// content first, then the Sentari-managed block delimited by sentinel
// comments.  netrc is whitespace-separated; we use one record per
// line for readability, two-space indents on continuation lines per
// netrc(5) convention.
func renderNetrcMerged(preserved []byte, creds []pipNetrcCred, marker MarkerFields) ([]byte, error) {
	if err := validateMarkerKeyID(marker.KeyID); err != nil {
		return nil, fmt.Errorf("renderNetrcMerged: %w", err)
	}

	var b strings.Builder
	if len(preserved) > 0 {
		b.Write(preserved)
		if preserved[len(preserved)-1] != '\n' {
			b.WriteByte('\n')
		}
	}
	b.WriteString(netrcBlockStart)
	b.WriteString("\n")
	b.WriteString(renderHashMarker(marker))
	for _, c := range creds {
		// Per netrc(5), tokens are whitespace-separated; passwords
		// containing whitespace must NOT contain spaces (no portable
		// quoting in netrc).  Server-side validation refuses
		// whitespace in tokens / passwords / usernames; this is a
		// defensive guard that drops the record if validation
		// somehow let one slip through, so we never produce a
		// silently-corrupt netrc.
		if strings.ContainsAny(c.Host, " \t\r\n") ||
			strings.ContainsAny(c.Login, " \t\r\n") ||
			strings.ContainsAny(c.Password, " \t\r\n") {
			return nil, fmt.Errorf("renderNetrcMerged: credential field contains whitespace (host=%q)", c.Host)
		}
		fmt.Fprintf(&b, "machine %s\n  login %s\n  password %s\n", c.Host, c.Login, c.Password)
	}
	b.WriteString(netrcBlockEnd)
	b.WriteString("\n")
	return []byte(b.String()), nil
}

// stripNetrcSentariBlock returns ``content`` with any single Sentari-
// managed block removed.  Same shape as the npm helper, just with
// netrc sentinels.  A start without a matching end is treated as
// "block runs to EOF" — conservative: better to drop too much of our
// own state than to leave a half-block that confuses next-apply.
func stripNetrcSentariBlock(content []byte) []byte {
	if len(content) == 0 {
		return nil
	}
	lines := strings.Split(string(content), "\n")
	out := make([]string, 0, len(lines))
	inBlock := false
	for _, line := range lines {
		trimmed := strings.TrimRight(line, "\r")
		if !inBlock && trimmed == netrcBlockStart {
			inBlock = true
			continue
		}
		if inBlock {
			if trimmed == netrcBlockEnd {
				inBlock = false
			}
			continue
		}
		out = append(out, line)
	}
	joined := strings.Join(out, "\n")
	joined = strings.TrimRight(joined, "\n")
	if joined == "" {
		return nil
	}
	return []byte(joined)
}

// netrcHostOf extracts the bare host (no scheme, no port) from a
// registry URL for netrc lookup.  Distinct from ``hostOf`` in pip.go
// because that one is host-list-for-pip-trusted-host-line specific;
// netrc accepts hosts with neither scheme nor port (RFC 1738
// "machine name").
func netrcHostOf(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", err
	}
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("URL has no host component: %q", rawURL)
	}
	return host, nil
}
