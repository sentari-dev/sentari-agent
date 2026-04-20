//go:build windows

package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// windowsRegistryScanner discovers Python installations registered in the
// Windows Registry.  The official Python installer writes entries under
// HKLM\SOFTWARE\Python\PythonCore\<version>\InstallPath (machine-wide)
// and HKCU\...\PythonCore\<version>\InstallPath (per-user).  Reading the
// registry bypasses the filesystem depth limit that would otherwise miss
// deep AppData installs.
//
// Emitted Environments carry EnvType=EnvPip (these are standard global
// Python site-packages, not venvs) and Scan() delegates to the pip parser.
type windowsRegistryScanner struct{}

func (windowsRegistryScanner) EnvType() string { return envWindowsRegistry }

func (windowsRegistryScanner) DiscoverAll(_ context.Context) ([]Environment, []ScanError) {
	var envs []Environment
	var errs []ScanError
	seen := make(map[string]bool)

	roots := []registry.Key{registry.LOCAL_MACHINE, registry.CURRENT_USER}
	// Include the WOW64 32-bit path for 32-bit Python on 64-bit Windows.
	subKeys := []string{
		`SOFTWARE\Python\PythonCore`,
		`SOFTWARE\WOW6432Node\Python\PythonCore`,
	}

	for _, root := range roots {
		for _, sub := range subKeys {
			k, err := registry.OpenKey(root, sub, registry.ENUMERATE_SUB_KEYS|registry.READ)
			if err != nil {
				continue // Key absent — Python not registered here.
			}
			versions, err := k.ReadSubKeyNames(-1)
			k.Close()
			if err != nil {
				continue
			}

			for _, ver := range versions {
				installPath, err := readRegistryInstallPath(root, sub, ver)
				if err != nil || installPath == "" {
					continue
				}
				sitePackages := filepath.Join(installPath, "Lib", "site-packages")
				info, serr := os.Stat(sitePackages)
				if serr != nil || !info.IsDir() {
					continue
				}
				key := strings.ToLower(filepath.Clean(sitePackages))
				if seen[key] {
					continue
				}
				seen[key] = true
				envs = append(envs, Environment{
					EnvType: EnvPip, // tag emitted packages as pip
					Path:    sitePackages,
					Name:    "python-" + ver,
				})
			}
		}
	}

	return envs, errs
}

func (windowsRegistryScanner) Scan(_ context.Context, env Environment) ([]PackageRecord, []ScanError) {
	return scanPipEnvironment(env.Path)
}

// readRegistryInstallPath reads the default string value from
// SOFTWARE\Python\PythonCore\<ver>\InstallPath.
func readRegistryInstallPath(root registry.Key, sub, ver string) (string, error) {
	keyPath := sub + `\` + ver + `\InstallPath`
	k, err := registry.OpenKey(root, keyPath, registry.QUERY_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()

	// The default value ("") holds the install directory.
	path, _, err := k.GetStringValue("")
	if err != nil {
		// Some installers store it under "ExecutablePath" instead.
		path, _, err = k.GetStringValue("ExecutablePath")
		if err != nil {
			return "", err
		}
		// ExecutablePath points to the python.exe; take the directory.
		path = filepath.Dir(path)
	}
	return path, nil
}

// readWindowsMachineGUID reads the stable machine GUID from the Windows
// registry — the same value used by Windows Update and licensing systems.
// Returns "" if the registry key is not accessible.
func readWindowsMachineGUID() string {
	k, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return ""
	}
	defer k.Close()

	guid, _, err := k.GetStringValue("MachineGuid")
	if err != nil {
		return ""
	}
	return guid
}
