package hardening

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// collectDiskEncryption reports whether the ROOT filesystem sits on a
// dm-crypt/LUKS mapping (Linux, full tier). Evidence, in precedence order:
//
//   - the device-mapper block that actually backs "/" (resolved via
//     /proc/self/mountinfo) is a LUKS mapping — directly, or through a dm slave
//     ancestor (LVM-on-LUKS), OR
//   - a root ("/" target) entry in /etc/crypttab — configured encryption.
//
// Honesty rules (a compliant host must never read as failing, and a plaintext
// root with an unrelated encrypted DATA disk must never read as passing):
//
//   - true  ⇒ positive evidence the ROOT device is encrypted.
//   - false ⇒ we could authoritatively read a source (the root dm mapping, or a
//     present crypttab) and it shows no root encryption.
//   - unknown ⇒ we could read NEITHER authoritative source (sysfs/mountinfo
//     unreadable AND no crypttab) — never a false FAIL.
//
// Note we deliberately do NOT treat any dm-* LUKS mapping as proof: an encrypted
// secondary volume on a plaintext-root host would otherwise fabricate a PASS.
// sysBlockRoot is "/sys/class/block", crypttabPath "/etc/crypttab", and
// mountinfoPath "/proc/self/mountinfo" in production; fixture paths in tests.
func collectDiskEncryption(sysBlockRoot, crypttabPath, mountinfoPath string) []Observation {
	key := familyDiskEncryption + ".root_encrypted"

	rootLUKS, srcPath, resolved := rootOnLUKS(sysBlockRoot, mountinfoPath)
	if resolved && rootLUKS {
		return []Observation{obsValue(key, familyDiskEncryption, "true", srcPath, "")}
	}

	// Declarative fallback: /etc/crypttab.
	data, sha, reason := readSource(crypttabPath, maxConfigFileSize)
	switch reason {
	case "":
		// crypttab read successfully — an authoritative declarative source.
		if crypttabHasEncryptedRoot(data) {
			return []Observation{obsValue(key, familyDiskEncryption, "true", crypttabPath, sha)}
		}
		return []Observation{obsValue(key, familyDiskEncryption, "false", crypttabPath, sha)}
	case "not found":
		// No declarative crypttab. If we positively resolved the root device
		// (and it is NOT on LUKS) that is genuine evidence of an unencrypted
		// root ⇒ false. If sysfs/mountinfo could not be read there is no
		// authoritative source at all ⇒ honest unknown (never a false FAIL).
		if resolved {
			return []Observation{obsValue(key, familyDiskEncryption, "false", sysBlockRoot, "")}
		}
		return []Observation{obsError(key, familyDiskEncryption, crypttabPath, "root device unresolved and no crypttab")}
	default:
		// crypttab present but unreadable (permission/other). Defer to the dm
		// resolution when we have it; otherwise unknown.
		if resolved {
			return []Observation{obsValue(key, familyDiskEncryption, "false", sysBlockRoot, "")}
		}
		return []Observation{obsError(key, familyDiskEncryption, crypttabPath, reason)}
	}
}

// rootOnLUKS resolves the block device backing "/" and reports whether it is a
// LUKS dm-crypt mapping. The returned `resolved` is true only when we could
// actually read the root device (mountinfo + sysfs); when it is false the
// caller must NOT infer "unencrypted" from the silence.
func rootOnLUKS(sysBlockRoot, mountinfoPath string) (isLUKS bool, srcPath string, resolved bool) {
	rootDev, ok := rootDeviceMajorMinor(mountinfoPath)
	if !ok {
		return false, "", false // could not resolve the root device
	}
	entries, err := os.ReadDir(sysBlockRoot)
	if err != nil {
		return false, "", false // sysfs unreadable ⇒ unknown, not "unencrypted"
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "dm-") {
			continue
		}
		b, err := safeio.ReadFile(filepath.Join(sysBlockRoot, e.Name(), "dev"), maxProcFileSize)
		if err != nil {
			continue
		}
		if strings.TrimSpace(string(b)) != rootDev {
			continue
		}
		// This dm device backs "/". Is it — or a dm slave ancestor
		// (LVM-on-LUKS) — a LUKS mapping?
		if luks, p := dmIsLUKS(sysBlockRoot, e.Name(), 0); luks {
			return true, p, true
		}
		return false, "", true // root dm resolved, not LUKS
	}
	// Root device is not a dm mapping at all ⇒ authoritatively not dm-encrypted.
	return false, "", true
}

// dmIsLUKS reports whether a device-mapper node (or one of its dm slave
// ancestors) is a LUKS mapping, by reading dm/uuid ("CRYPT-LUKS…"). The slave
// walk catches LVM-on-LUKS, where the root LV's uuid is LVM-… but its
// underlying PV is the crypt device. Depth-bounded against a pathological
// sysfs graph.
func dmIsLUKS(sysBlockRoot, name string, depth int) (bool, string) {
	if depth > 8 {
		return false, ""
	}
	uuidPath := filepath.Join(sysBlockRoot, name, "dm", "uuid")
	if b, err := safeio.ReadFile(uuidPath, maxProcFileSize); err == nil {
		if strings.HasPrefix(strings.TrimSpace(string(b)), "CRYPT-LUKS") {
			return true, uuidPath
		}
	}
	slaves, err := os.ReadDir(filepath.Join(sysBlockRoot, name, "slaves"))
	if err != nil {
		return false, ""
	}
	for _, s := range slaves {
		if !strings.HasPrefix(s.Name(), "dm-") {
			continue
		}
		if luks, p := dmIsLUKS(sysBlockRoot, s.Name(), depth+1); luks {
			return true, p
		}
	}
	return false, ""
}

// rootDeviceMajorMinor returns the "major:minor" of the device mounted at "/"
// from a mountinfo file. mountinfo field layout: [0] mount-id, [1] parent-id,
// [2] major:minor, [3] root, [4] mount-point, … . Read through the config cap
// (mountinfo can exceed the small /proc scalar cap on a busy host).
func rootDeviceMajorMinor(mountinfoPath string) (string, bool) {
	b, err := safeio.ReadFile(mountinfoPath, maxConfigFileSize)
	if err != nil {
		return "", false
	}
	for _, raw := range strings.Split(string(b), "\n") {
		fields := strings.Fields(raw)
		if len(fields) < 5 {
			continue
		}
		if fields[4] == "/" {
			return fields[2], true
		}
	}
	return "", false
}

// crypttabHasEncryptedRoot reports whether /etc/crypttab declares a mapping
// whose name suggests the root volume (root/cryptroot/luks-root/…). crypttab
// lines are "<name> <device> [keyfile] [options]".
func crypttabHasEncryptedRoot(data []byte) bool {
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		name := strings.ToLower(fields[0])
		if name == "root" || strings.Contains(name, "root") || strings.HasPrefix(name, "cryptroot") || strings.HasPrefix(name, "luks") {
			return true
		}
	}
	return false
}
