//go:build !darwin && !linux && !windows

package update

import "errors"

// restartService is a no-op on platforms without a supported service manager
// (darwin=launchd, linux=systemd, windows=SCM each have their own file).
// Returning an error here so the operator sees a clear "manual restart
// required" message rather than thinking the upgrade completed cleanly.
func restartService(_ string) error {
	return errors.New("automatic service restart not implemented on this platform; restart manually")
}
