// Package runtime detects what kind of host the agent is running
// on: bare_metal, container, k8s, or unknown.  Cross-platform stub
// that delegates to per-OS implementations.
//
// Sentari §15a.1 Phase 2b — server-side machinery shipped in
// sentari PR #79.  This module emits the value on every /scan;
// the server applies the propose-then-approve workflow.
//
// The four enum values match exactly what the server validates
// against — keep them in lockstep.
package runtime

// Enum values.  Mirror sentari/server/services/device_runtime.py:
// VALID_RUNTIMES.
const (
	BareMetal = "bare_metal"
	Container = "container"
	K8s       = "k8s"
	Unknown   = "unknown"
)

// Detect returns one of the four enum values.  Always succeeds —
// returns Unknown on any probe error rather than propagating it
// so the agent's scan cycle is never blocked by detection.
func Detect() string {
	return detect()
}
