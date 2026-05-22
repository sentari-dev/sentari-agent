//go:build linux

package update

import (
	"fmt"
	"os/exec"
)

const linuxSystemdUnit = "sentari-agent.service"

// restartService asks systemd to restart the sentari-agent unit.
// Operators who run the agent under sysvinit / a custom supervisor
// need to wire their own post-install hook; that path is rare enough
// to defer to a follow-up (the cross-platform interface accepts a
// future ``--restart-cmd`` plug-in point without breaking callers).
func restartService(_ string) error {
	cmd := exec.Command("/usr/bin/systemctl", "restart", linuxSystemdUnit)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart %s: %w (output: %s)", linuxSystemdUnit, err, out)
	}
	return nil
}
