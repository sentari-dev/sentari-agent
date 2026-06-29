// Package runtime detects what kind of host the agent is running
// on: bare_metal, container, k8s, or unknown.  Cross-platform stub
// that delegates to per-OS implementations.
//
// This module emits the detected value on every /scan; the server
// applies a propose-then-approve workflow before trusting it.
//
// The four enum values match exactly what the server validates
// against — keep them in lockstep.
package runtime

// Enum values.  Mirror the server's runtime-detection enum
// (VALID_RUNTIMES).
const (
	BareMetal = "bare_metal"
	Container = "container"
	K8s       = "k8s"
	Unknown   = "unknown"
)

// Detect returns one of the four enum values.  Always succeeds —
// the per-OS implementations swallow probe errors.
//
// Behaviour today: when a Linux-specific probe (``/proc/1/cgroup``,
// ``/run/.containerenv``) fails or doesn't exist (macOS, hardened
// containers with masked ``/proc``, permission denied), the
// implementation falls through to ``BareMetal`` rather than
// returning ``Unknown``.  ``Unknown`` is reserved for future
// scenarios where the detector itself can't make an informed call
// — e.g. a Windows WMI follow-up that explicitly errors out.
// Operators who know the auto-detection guessed wrong can override
// the value via the dashboard's
// ``PUT /api/v1/inventory/devices/{id}/runtime`` admin endpoint.
func Detect() string {
	return detect()
}
