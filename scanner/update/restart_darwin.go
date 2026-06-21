//go:build darwin

package update

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
)

// defaultDarwinLaunchdLabel matches the label used by the install-time
// LaunchDaemons plist (deploy/macos/...).  Operators who install
// under a different label override via SENTARI_AGENT_LAUNCHD_LABEL.
const defaultDarwinLaunchdLabel = "system/dev.sentari.agent"

// validLaunchdTarget is the allow-list pattern an operator-supplied
// launchd service target (SENTARI_AGENT_LAUNCHD_LABEL) must match
// before it is handed to exec on the self-update restart path.  It
// accepts the launchctl service-target grammar: one or more ``/``-
// separated segments (e.g. ``system/dev.sentari.agent`` or
// ``gui/501/dev.sentari.agent``), each a reverse-DNS-style label of
// letters, digits, ``.``, ``-`` and ``_``.  Each segment's leading
// character is constrained to an alphanumeric so a value like
// ``-malformed`` cannot be smuggled in as a launchctl option and a
// ``.hidden`` / ``..`` traversal segment is rejected.  Anything
// outside this set (whitespace, shell metacharacters, path traversal,
// embedded newlines, empty / doubled separators) is refused before
// exec.
var validLaunchdTarget = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$`)

// cmdRunner runs a service-management command and returns its
// combined output.  A package-level variable so tests can stub it
// out without spawning real launchctl invocations — covers the
// 2026-05-22 launchd-label regression where the unit-test suite
// never noticed the hardcoded ``system/com.sentari.agent`` mismatch.
var cmdRunner = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// restartService asks launchd to bounce the sentari-agent daemon so
// the freshly-installed binary takes effect.  ``binaryPath`` is the
// install path of the just-replaced binary; on darwin we don't use
// it directly but the cross-platform interface stays consistent.
//
// The label can be overridden via the SENTARI_AGENT_LAUNCHD_LABEL env
// var, e.g. ``system/com.example.sentari``.  An empty value falls
// back to ``defaultDarwinLaunchdLabel``.
func restartService(_ string) error {
	label := os.Getenv("SENTARI_AGENT_LAUNCHD_LABEL")
	if label == "" {
		label = defaultDarwinLaunchdLabel
	}
	// Refuse anything outside the strict allow-list before exec — the
	// label reaches a privileged launchctl invocation and an
	// unvalidated env var is an injection vector (option smuggling,
	// path traversal, embedded newlines).
	if !validLaunchdTarget.MatchString(label) {
		return fmt.Errorf("refusing to restart: invalid launchd label %q", label)
	}
	out, err := cmdRunner("/bin/launchctl", "kickstart", "-k", label)
	if err != nil {
		return fmt.Errorf("launchctl kickstart %s: %w (output: %s)", label, err, out)
	}
	return nil
}
