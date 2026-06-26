package update

import (
	"fmt"
	"regexp"
)

// defaultWindowsServiceName is the service name the install-time package
// registers with the Windows Service Control Manager.  Operators who install
// under a different name override via SENTARI_AGENT_SERVICE_NAME.
const defaultWindowsServiceName = "SentariAgent"

// validWindowsServiceName is the allow-list a service name must match before
// it is interpolated into the sc.exe command line.  Windows service names
// already exclude '/' and '\'; we constrain further to a conservative set so
// the value cannot smuggle sc.exe options, shell metacharacters, or quoting
// past the restart helper.  Mirrors the hardening on the Linux systemd path.
var validWindowsServiceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// windowsServiceName resolves and validates the service name from the
// operator-supplied environment value (empty => default).  Pure and
// host-testable; the Windows-only restart_windows.go calls it.
func windowsServiceName(envValue string) (string, error) {
	name := envValue
	if name == "" {
		name = defaultWindowsServiceName
	}
	if !validWindowsServiceName.MatchString(name) {
		return "", fmt.Errorf("refusing to restart: invalid Windows service name %q", name)
	}
	return name, nil
}

// windowsRestartCommandLine builds the cmd.exe argument that stops then starts
// the service.  A service cannot cleanly restart itself in-process — issuing
// the stop terminates the agent before the start runs — so the restart is
// delegated to a detached cmd.exe that pauses for the SCM to settle the STOP
// before issuing START.  Kept pure so the exact command is unit-testable
// without a Windows host.
func windowsRestartCommandLine(name string) string {
	return fmt.Sprintf("sc stop %s & timeout /t 3 /nobreak >NUL & sc start %s", name, name)
}
