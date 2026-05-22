//go:build darwin

package update

import (
	"fmt"
	"os"
	"os/exec"
)

// defaultDarwinLaunchdLabel matches the label used by the install-time
// LaunchDaemons plist (deploy/macos/...).  Operators who install
// under a different label override via SENTARI_AGENT_LAUNCHD_LABEL.
const defaultDarwinLaunchdLabel = "system/dev.sentari.agent"

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
	cmd := exec.Command("/bin/launchctl", "kickstart", "-k", label)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl kickstart %s: %w (output: %s)", label, err, out)
	}
	return nil
}
