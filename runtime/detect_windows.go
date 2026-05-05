//go:build windows

package runtime

import "os"

// detect on Windows: Phase 2b ships with the env-var probe only.
// WMI-based container/VM detection is a follow-up — the cost/value
// of wrong-Windows-detection is low because the install-gate threat
// model on Windows is dominated by EXE installers, not package-
// manager registries running inside Windows containers.  Operators
// can override via ``PUT /api/v1/inventory/devices/{id}/runtime``
// when the auto-detection guesses wrong.
func detect() string {
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return K8s
	}
	return BareMetal
}
