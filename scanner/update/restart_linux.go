//go:build linux

package update

import (
	"fmt"
	"os"
	"os/exec"
)

const defaultLinuxSystemdUnit = "sentari-agent.service"

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
	cmd := exec.Command("/usr/bin/systemctl", "restart", unit)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %w (output: %s)", unit, err, out)
	}
	return nil
}
