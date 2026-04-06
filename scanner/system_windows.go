//go:build windows

package scanner

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// discoverWindowsRegistryEnvs discovers Python installations registered in the
// Windows Registry. The official Python installer always writes entries under
// HKLM\SOFTWARE\Python\PythonCore\<version>\InstallPath (machine-wide) and
// HKCU\...\PythonCore\<version>\InstallPath (per-user). This bypasses the
// filesystem depth limit that would otherwise miss deep AppData installs.
func discoverWindowsRegistryEnvs() ([]discoveredEnv, []ScanError) {
	var envs []discoveredEnv
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

				// The primary site-packages location for an official Python install.
				sitePackages := filepath.Join(installPath, "Lib", "site-packages")
				if info, serr := os.Stat(sitePackages); serr == nil && info.IsDir() {
					key := strings.ToLower(filepath.Clean(sitePackages))
					if !seen[key] {
						seen[key] = true
						envs = append(envs, discoveredEnv{
							path:    sitePackages,
							envType: EnvPip,
							name:    "python-" + ver,
						})
					}
				}
			}
		}
	}

	return envs, errs
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
