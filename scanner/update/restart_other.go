//go:build !darwin && !linux

package update

import "errors"

// restartService is a no-op on non-darwin/linux platforms — Windows
// service control is on the roadmap but each path needs its own
// platform-specific testing.  Returning an error here so the operator
// sees a clear "manual restart required" message rather than thinking
// the upgrade completed cleanly.
func restartService(_ string) error {
	return errors.New("automatic service restart not implemented on this platform; restart manually")
}
