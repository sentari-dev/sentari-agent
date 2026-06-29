//go:build windows

package update

import (
	"fmt"
	"os"
	"os/exec"

	"golang.org/x/sys/windows"
)

// startDetachedRestart launches the stop/start helper in a detached process so
// it survives this agent process being terminated when the SCM stops the
// service.  Var so tests on a Windows host can substitute it.
var startDetachedRestart = func(commandLine string) error {
	helper := exec.Command("cmd.exe", "/c", commandLine)
	// DETACHED_PROCESS + new process group: the helper must not die with the
	// agent and must not share its console (the service has none).
	helper.SysProcAttr = &windows.SysProcAttr{
		CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP,
	}
	if err := helper.Start(); err != nil {
		return fmt.Errorf("launch restart helper: %w", err)
	}
	// Release the child so it is fully detached; we do not Wait (the SCM stop
	// would kill us first anyway).
	return helper.Process.Release()
}

// restartService restarts the agent's Windows service via the Service Control
// Manager.  The service name defaults to "SentariAgent" and can be overridden
// with SENTARI_AGENT_SERVICE_NAME.
//
// NOTE: the in-process self-restart semantics (detached helper surviving the
// SCM-driven stop) need validation on a real Windows host before this path is
// relied on for unattended self-update; until then operators can still restart
// the service manually.
func restartService(_ string) error {
	name, err := windowsServiceName(os.Getenv("SENTARI_AGENT_SERVICE_NAME"))
	if err != nil {
		return err
	}
	return startDetachedRestart(windowsRestartCommandLine(name))
}
