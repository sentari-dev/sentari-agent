//go:build linux

package update

import (
	"fmt"
	"os"
	"os/exec"
	"regexp"
)

const defaultLinuxSystemdUnit = "sentari-agent.service"

// validSystemdUnit is the allow-list pattern an operator-supplied unit
// name (SENTARI_AGENT_SYSTEMD_UNIT) must match before it is handed to
// exec on the self-update restart path.  Systemd unit names are drawn
// from this character set; anything outside it (whitespace, shell
// metacharacters, path separators, newlines) is rejected.  The leading
// character is constrained to alphanumerics so a value like "--user"
// cannot be smuggled in as a systemctl option.
var validSystemdUnit = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]*$`)

// cmdRunner runs a service-management command and returns its
// combined output.  Variable so tests can stub it; see
// restart_darwin.go for the regression context.
var cmdRunner = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// restartService asks systemd to restart the sentari-agent unit.
// Operators who run the agent under sysvinit / a custom supervisor
// need to wire their own post-install hook; that path is rare enough
// to defer to a follow-up (the cross-platform interface accepts a
// future ``--restart-cmd`` plug-in point without breaking callers).
//
// The unit name can be overridden via SENTARI_AGENT_SYSTEMD_UNIT.
func restartService(_ string) error {
	unit := os.Getenv("SENTARI_AGENT_SYSTEMD_UNIT")
	if unit == "" {
		unit = defaultLinuxSystemdUnit
	}
	// Refuse anything outside the strict allow-list before exec — the
	// unit name reaches a privileged systemctl invocation and an
	// unvalidated env var is an injection vector (option smuggling,
	// path traversal, embedded newlines).
	if !validSystemdUnit.MatchString(unit) {
		return fmt.Errorf("refusing to restart: invalid systemd unit name %q", unit)
	}
	out, err := cmdRunner("/usr/bin/systemctl", "restart", unit)
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %w (output: %s)", unit, err, out)
	}
	return nil
}
