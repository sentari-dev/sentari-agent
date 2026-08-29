//go:build !linux && !windows && !darwin

package hardening

import "context"

// collectPlatform is a no-op on platforms without a hardening collector set.
// The server derives `not_applicable` for every family from the absent block.
func collectPlatform(_ context.Context) []Observation { return nil }
