//go:build windows

package runtimeversions

import (
	"strconv"

	"golang.org/x/sys/windows/registry"
)

// detectIIS reads HKLM\SOFTWARE\Microsoft\InetStp for IIS presence + version.
// Presence-only: no EOL feed (IIS lifecycle follows Windows Server).
func detectIIS() []InstalledRuntime {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\InetStp`, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()

	ver := ""
	if s, _, err := k.GetStringValue("VersionString"); err == nil {
		ver = parseVersionToken(s) // e.g. "Version 10.0" -> "10.0"
	}
	if ver == "" {
		major, _, e1 := k.GetIntegerValue("MajorVersion")
		minor, _, e2 := k.GetIntegerValue("MinorVersion")
		if e1 == nil {
			ver = strconv.FormatUint(major, 10)
			if e2 == nil {
				ver += "." + strconv.FormatUint(minor, 10)
			}
		}
	}
	path := `C:\inetpub`
	if p, _, err := k.GetStringValue("PathWWWRoot"); err == nil && p != "" {
		path = p
	}
	return []InstalledRuntime{mk("iis", ver, "Microsoft", path)}
}
