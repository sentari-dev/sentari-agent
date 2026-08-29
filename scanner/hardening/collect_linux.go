//go:build linux

package hardening

import "context"

// Real Linux source paths. Vars (not consts) so an operator-facing override or
// a future config knob could repoint them; the collectors themselves are
// platform-neutral and unit-tested against fixtures.
var (
	linuxSSHDConfig     = "/etc/ssh/sshd_config"
	linuxLoginDefs      = "/etc/login.defs"
	linuxPwquality      = "/etc/security/pwquality.conf"
	linuxFaillock       = "/etc/security/faillock.conf"
	linuxProcSysRoot    = "/proc/sys"
	linuxSysBlock       = "/sys/class/block"
	linuxCrypttab       = "/etc/crypttab"
	linuxMountinfo      = "/proc/self/mountinfo"
	linuxUFWConf        = "/etc/ufw/ufw.conf"
	linuxFirewalldDir   = "/etc/firewalld"
	linuxNftablesConf   = "/etc/nftables.conf"
	linuxAuditdConf     = "/etc/audit/auditd.conf"
	linuxAuditRulesFile = "/etc/audit/audit.rules"
	linuxAuditRulesDir  = "/etc/audit/rules.d"
	linuxAptAutoUpgrade = "/etc/apt/apt.conf.d/20auto-upgrades"
	linuxDnfAutomatic   = "/etc/dnf/automatic.conf"
	linuxDconfDir       = "/etc/dconf/db/local.d"
	linuxNginxConf      = "/etc/nginx/nginx.conf"
	linuxHttpdConf      = "/etc/httpd/conf.d/ssl.conf"
)

// collectPlatform runs the Linux hardening collectors. Each is guarded so one
// malformed source cannot abort the pass.
func collectPlatform(_ context.Context) []Observation {
	var obs []Observation
	obs = append(obs, guard(familySSH, func() []Observation { return collectSSH(linuxSSHDConfig) })...)
	obs = append(obs, guard(familyAuthPolicy, func() []Observation {
		return collectAuthPolicy(linuxLoginDefs, linuxPwquality, linuxFaillock)
	})...)
	obs = append(obs, guard(familyKernel, func() []Observation { return collectKernel(linuxProcSysRoot) })...)
	obs = append(obs, guard(familyDiskEncryption, func() []Observation {
		return collectDiskEncryption(linuxSysBlock, linuxCrypttab, linuxMountinfo)
	})...)
	obs = append(obs, guard(familyFirewall, func() []Observation {
		return collectFirewallLinux(linuxUFWConf, linuxFirewalldDir, linuxNftablesConf)
	})...)
	obs = append(obs, guard(familyAuditDaemon, func() []Observation {
		return collectAuditDaemon(linuxAuditdConf, linuxAuditRulesFile, linuxAuditRulesDir)
	})...)
	obs = append(obs, guard(familyAutoUpdate, func() []Observation {
		return collectAutoUpdateLinux(linuxAptAutoUpgrade, linuxDnfAutomatic)
	})...)
	obs = append(obs, guard(familyScreenLock, func() []Observation { return collectScreenLockLinux(linuxDconfDir) })...)
	obs = append(obs, guard(familyTLS, func() []Observation { return collectTLSLinux(linuxNginxConf, linuxHttpdConf) })...)
	return obs
}
