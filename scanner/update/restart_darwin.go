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
	out, err := cmdRunner("/bin/launchctl", "kickstart", "-k", label)
	if err != nil {
		return fmt.Errorf("launchctl kickstart %s: %w (output: %s)", label, err, out)
	}
	return nil
}
