// Package runtimeversions detects installed Python, Node, and JDK
// runtime versions on the local device. Output is one InstalledRuntime
// per detected install. Pure-Go file inspection — no binary invocation.
package runtimeversions

// InstalledRuntime mirrors the v3 payload's installed_runtimes entry.
// See docs/contracts/agent-scan-payload-v3.md.
type InstalledRuntime struct {
	Name        string `json:"name"`         // 'python' | 'node' | 'jdk'
	Version     string `json:"version"`      // full version e.g. '3.11.5'
	Cycle       string `json:"cycle"`        // derived from version
	Distro      string `json:"distro,omitempty"` // 'Temurin' etc. for JDK; empty for others
	InstallPath string `json:"install_path"`
}
