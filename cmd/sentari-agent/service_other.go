//go:build !windows && enterprise

package main

import "context"

// runServeUnderService is a no-op on non-Windows hosts: there is no Service
// Control Manager to dispatch to, so the daemon always runs via the console
// SIGINT/SIGTERM path (systemd/launchd deliver those signals directly).
// Returning ran=false tells the caller to take that path unchanged.
func runServeUnderService(_ func(ctx context.Context, shutdownReason func() string)) (ran bool, err error) {
	return false, nil
}
