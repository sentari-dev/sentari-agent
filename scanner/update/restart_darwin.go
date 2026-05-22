//go:build darwin

package update

import (
	"fmt"
	"os/exec"
)

// restartService asks launchd to bounce the sentari-agent daemon so
// the freshly-installed binary takes effect.  The daemon label is the
// reverse-DNS form used by the install-time plist; if the operator
// installed under a different label the kickstart will fail and the
// caller surfaces the wrap.
const darwinLaunchdLabel = "system/com.sentari.agent"

// restartService implements the darwin half of the cross-platform
// restart hook called by Apply / Rollback.  ``binaryPath`` is the
// install path of the just-replaced binary; on darwin we only need
// the launchd label, but linux uses it to choose between systemd
// unit names, so the interface stays consistent.
func restartService(_ string) error {
	cmd := exec.Command("/bin/launchctl", "kickstart", "-k", darwinLaunchdLabel)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("launchctl kickstart %s: %w (output: %s)", darwinLaunchdLabel, err, out)
	}
	return nil
}
