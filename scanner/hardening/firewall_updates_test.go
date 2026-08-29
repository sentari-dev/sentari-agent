package hardening

import (
	"path/filepath"
	"testing"
)

// --- firewall (Linux, config-derived partial tier) --------------------------

func TestCollectFirewallLinux_UFWEnabled(t *testing.T) {
	obs := collectFirewallLinux(
		filepath.Join("testdata", "ufw.conf"),
		filepath.Join(t.TempDir(), "no-firewalld"),
		filepath.Join(t.TempDir(), "no-nft"),
	)
	assertValue(t, mustObs(t, obs, "firewall.enabled"), "true")
}

func TestCollectFirewallLinux_UFWDisabled(t *testing.T) {
	dir := t.TempDir()
	ufw := writeTemp(t, dir, "ufw.conf", "ENABLED=no\nLOGLEVEL=low\n")
	obs := collectFirewallLinux(ufw, filepath.Join(dir, "x"), filepath.Join(dir, "y"))
	assertValue(t, mustObs(t, obs, "firewall.enabled"), "false")
}

func TestCollectFirewallLinux_FirewalldDir(t *testing.T) {
	dir := t.TempDir()
	fwd := filepath.Dir(writeTemp(t, dir, "firewalld/firewalld.conf", "DefaultZone=public\n"))
	obs := collectFirewallLinux(filepath.Join(dir, "no-ufw"), fwd, filepath.Join(dir, "no-nft"))
	assertValue(t, mustObs(t, obs, "firewall.enabled"), "true")
}

// TestCollectFirewallLinux_FirewalldInstalledNotEnabled: the firewalld config
// dir exists (installed) but firewalld.conf has no DefaultZone => UNKNOWN, not a
// false PASS (finding #7 regression guard).
func TestCollectFirewallLinux_FirewalldInstalledNotEnabled(t *testing.T) {
	dir := t.TempDir()
	// dir exists with a conf that has no DefaultZone.
	fwd := filepath.Dir(writeTemp(t, dir, "firewalld/firewalld.conf", "# CleanupOnExit=yes\nLogDenied=off\n"))
	obs := collectFirewallLinux(filepath.Join(dir, "no-ufw"), fwd, filepath.Join(dir, "no-nft"))
	assertUnknown(t, mustObs(t, obs, "firewall.enabled"), "")

	// dir exists but no firewalld.conf at all => also unknown, never true.
	dir2 := t.TempDir()
	bare := writeTemp(t, dir2, "firewalld/.keep", "")
	obs = collectFirewallLinux(filepath.Join(dir2, "no-ufw"), filepath.Dir(bare), filepath.Join(dir2, "no-nft"))
	assertUnknown(t, mustObs(t, obs, "firewall.enabled"), "")
}

func TestCollectFirewallLinux_Nftables(t *testing.T) {
	dir := t.TempDir()
	nft := writeTemp(t, dir, "nftables.conf", "#!/usr/sbin/nft -f\ntable inet filter {\n}\n")
	obs := collectFirewallLinux(filepath.Join(dir, "no-ufw"), filepath.Join(dir, "no-fwd"), nft)
	assertValue(t, mustObs(t, obs, "firewall.enabled"), "true")

	empty := writeTemp(t, dir, "empty-nft.conf", "# no tables here\n")
	obs = collectFirewallLinux(filepath.Join(dir, "no-ufw"), filepath.Join(dir, "no-fwd"), empty)
	assertValue(t, mustObs(t, obs, "firewall.enabled"), "false")
}

func TestCollectFirewallLinux_NoConfig(t *testing.T) {
	dir := t.TempDir()
	obs := collectFirewallLinux(
		filepath.Join(dir, "no-ufw"), filepath.Join(dir, "no-fwd"), filepath.Join(dir, "no-nft"),
	)
	assertUnknown(t, mustObs(t, obs, "firewall.enabled"), "no firewall config found")
}

func TestBoolStr(t *testing.T) {
	if boolStr(true) != "true" || boolStr(false) != "false" {
		t.Fatal("boolStr wrong")
	}
}

// --- audit daemon (Linux, full tier) ----------------------------------------

func TestCollectAuditDaemon_ConfigAndRules(t *testing.T) {
	dir := t.TempDir()
	conf := writeTemp(t, dir, "auditd.conf", "log_file = /var/log/audit/audit.log\n")
	rules := writeTemp(t, dir, "audit.rules", "-w /etc/passwd -p wa\n")
	obs := collectAuditDaemon(conf, rules, filepath.Join(dir, "rules.d"))
	assertValue(t, mustObs(t, obs, "audit_daemon.enabled"), "true")
}

func TestCollectAuditDaemon_RulesDir(t *testing.T) {
	dir := t.TempDir()
	conf := writeTemp(t, dir, "auditd.conf", "x=1\n")
	rulesDir := filepath.Dir(writeTemp(t, dir, "rules.d/10-base.rules", "-w /etc/shadow -p wa\n"))
	obs := collectAuditDaemon(conf, filepath.Join(dir, "no-audit.rules"), rulesDir)
	assertValue(t, mustObs(t, obs, "audit_daemon.enabled"), "true")
}

func TestCollectAuditDaemon_ConfigButNoRules(t *testing.T) {
	dir := t.TempDir()
	conf := writeTemp(t, dir, "auditd.conf", "x=1\n")
	obs := collectAuditDaemon(conf, filepath.Join(dir, "none.rules"), filepath.Join(dir, "empty.d"))
	assertValue(t, mustObs(t, obs, "audit_daemon.enabled"), "false")
}

func TestCollectAuditDaemon_NotInstalled(t *testing.T) {
	dir := t.TempDir()
	obs := collectAuditDaemon(
		filepath.Join(dir, "no-conf"), filepath.Join(dir, "no-rules"), filepath.Join(dir, "no-d"),
	)
	// No auditd.conf => not installed => false.
	assertValue(t, mustObs(t, obs, "audit_daemon.enabled"), "false")
}

// --- auto update (Linux, full tier) -----------------------------------------

func TestCollectAutoUpdateLinux_APTEnabled(t *testing.T) {
	obs := collectAutoUpdateLinux(
		filepath.Join("testdata", "20auto-upgrades"),
		filepath.Join(t.TempDir(), "no-dnf"),
	)
	assertValue(t, mustObs(t, obs, "auto_update.enabled"), "true")
}

func TestCollectAutoUpdateLinux_APTDisabled(t *testing.T) {
	dir := t.TempDir()
	apt := writeTemp(t, dir, "20auto-upgrades", `APT::Periodic::Unattended-Upgrade "0";`+"\n")
	obs := collectAutoUpdateLinux(apt, filepath.Join(dir, "no-dnf"))
	assertValue(t, mustObs(t, obs, "auto_update.enabled"), "false")
}

func TestCollectAutoUpdateLinux_DNF(t *testing.T) {
	dir := t.TempDir()
	dnf := writeTemp(t, dir, "automatic.conf", "[commands]\napply_updates = yes\n")
	obs := collectAutoUpdateLinux(filepath.Join(dir, "no-apt"), dnf)
	assertValue(t, mustObs(t, obs, "auto_update.enabled"), "true")
}

func TestCollectAutoUpdateLinux_None(t *testing.T) {
	dir := t.TempDir()
	obs := collectAutoUpdateLinux(filepath.Join(dir, "no-apt"), filepath.Join(dir, "no-dnf"))
	assertUnknown(t, mustObs(t, obs, "auto_update.enabled"), "no auto-update config found")
}

// --- screen lock (Linux dconf, partial tier) --------------------------------

func TestCollectScreenLockLinux_Fixture(t *testing.T) {
	obs := collectScreenLockLinux(filepath.Join("testdata", "dconf.d"))
	assertValue(t, mustObs(t, obs, "screen_lock.enabled"), "true")
	// lock-delay=uint32 30 => GVariant type prefix stripped.
	assertValue(t, mustObs(t, obs, "screen_lock.timeout_secs"), "30")
}

func TestCollectScreenLockLinux_NoPolicy(t *testing.T) {
	obs := collectScreenLockLinux(filepath.Join(t.TempDir(), "absent-dconf"))
	assertUnknown(t, mustObs(t, obs, "screen_lock.enabled"), "no system dconf screensaver policy")
	assertUnknown(t, mustObs(t, obs, "screen_lock.timeout_secs"), "no system dconf screensaver policy")
}

func TestCollectScreenLockLinux_IdleDelayFallback(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "dconf/00-ss", "[org/gnome/desktop/screensaver]\nlock-enabled=false\nidle-delay=uint32 900\n")
	obs := collectScreenLockLinux(filepath.Join(dir, "dconf"))
	assertValue(t, mustObs(t, obs, "screen_lock.enabled"), "false")
	// No lock-delay => falls back to idle-delay.
	assertValue(t, mustObs(t, obs, "screen_lock.timeout_secs"), "900")
}

func TestCollectScreenLockLinux_KeysAbsent(t *testing.T) {
	dir := t.TempDir()
	// Section present but neither lock-enabled nor any delay key.
	writeTemp(t, dir, "dconf/00-ss", "[org/gnome/desktop/screensaver]\npicture-uri=none\n")
	obs := collectScreenLockLinux(filepath.Join(dir, "dconf"))
	assertUnknown(t, mustObs(t, obs, "screen_lock.enabled"), "lock-enabled not set")
	assertUnknown(t, mustObs(t, obs, "screen_lock.timeout_secs"), "lock-delay not set")
}

func TestParseINISection(t *testing.T) {
	data := []byte("[a]\nx = 1\n[org/gnome/desktop/screensaver]\nlock-enabled=true\nlock-delay=uint32 30\n[b]\ny=2\n")
	g, ok := parseINISection(data, "org/gnome/desktop/screensaver")
	if !ok {
		t.Fatal("section not found")
	}
	if g["lock-enabled"] != "true" || g["lock-delay"] != "uint32 30" {
		t.Fatalf("section map wrong: %v", g)
	}
	if _, ok := parseINISection(data, "no/such/section"); ok {
		t.Error("missing section reported found")
	}
}

func TestStripDconfTypeAndBool(t *testing.T) {
	if stripDconfType("uint32 300") != "300" {
		t.Error("uint32 prefix not stripped")
	}
	if stripDconfType("int64 5") != "5" {
		t.Error("int64 prefix not stripped")
	}
	if stripDconfType("42") != "42" {
		t.Error("plain int mangled")
	}
	if normalizeDconfBool(" true ") != "true" || normalizeDconfBool("false") != "false" || normalizeDconfBool("nonsense") != "false" {
		t.Error("normalizeDconfBool wrong")
	}
}

// --- TLS (Linux web-server config, partial tier) ----------------------------

func TestCollectTLSLinux_Nginx(t *testing.T) {
	obs := collectTLSLinux(
		filepath.Join("testdata", "nginx.conf"),
		filepath.Join(t.TempDir(), "no-httpd"),
	)
	assertValue(t, mustObs(t, obs, "tls.min_version"), "TLSv1.2 TLSv1.3")
	assertValue(t, mustObs(t, obs, "tls.ciphers"), "HIGH:!aNULL:!MD5")
}

func TestCollectTLSLinux_Apache(t *testing.T) {
	dir := t.TempDir()
	httpd := writeTemp(t, dir, "ssl.conf", "SSLProtocol -all +TLSv1.2\nSSLCipherSuite HIGH:!aNULL\n")
	obs := collectTLSLinux(filepath.Join(dir, "no-nginx"), httpd)
	assertValue(t, mustObs(t, obs, "tls.min_version"), "-all +TLSv1.2")
	assertValue(t, mustObs(t, obs, "tls.ciphers"), "HIGH:!aNULL")
}

func TestCollectTLSLinux_DirectivesAbsent(t *testing.T) {
	dir := t.TempDir()
	nginx := writeTemp(t, dir, "nginx.conf", "http {\n  server_name example;\n}\n")
	obs := collectTLSLinux(nginx, filepath.Join(dir, "no-httpd"))
	assertUnknown(t, mustObs(t, obs, "tls.min_version"), "protocol directive not set")
	assertUnknown(t, mustObs(t, obs, "tls.ciphers"), "cipher directive not set")
}

func TestCollectTLSLinux_NoConfig(t *testing.T) {
	dir := t.TempDir()
	obs := collectTLSLinux(filepath.Join(dir, "no-nginx"), filepath.Join(dir, "no-httpd"))
	assertUnknown(t, mustObs(t, obs, "tls.min_version"), "no web-server TLS config found")
	assertUnknown(t, mustObs(t, obs, "tls.ciphers"), "no web-server TLS config found")
}

func TestNginxAndApacheDirective(t *testing.T) {
	nd := []byte("# c\nssl_protocols TLSv1.1;\nssl_protocols TLSv1.2 TLSv1.3;\n")
	if got := nginxDirective(nd, "ssl_protocols"); got != "TLSv1.2 TLSv1.3" { // last wins
		t.Errorf("nginxDirective=%q", got)
	}
	if got := nginxDirective(nd, "ssl_ciphers"); got != "" {
		t.Errorf("absent directive should be empty, got %q", got)
	}
	ad := []byte("sslprotocol -all +TLSv1.3\n")
	if got := apacheDirective(ad, "SSLProtocol"); got != "-all +TLSv1.3" { // case-insensitive
		t.Errorf("apacheDirective=%q", got)
	}
}

func TestAptUnattendedEnabled(t *testing.T) {
	if !aptUnattendedEnabled([]byte(`APT::Periodic::Unattended-Upgrade "1";`)) {
		t.Error("expected enabled for \"1\"")
	}
	if aptUnattendedEnabled([]byte("// APT::Periodic::Unattended-Upgrade \"1\";\n")) {
		t.Error("commented line must not count")
	}
	if aptUnattendedEnabled([]byte(`APT::Periodic::Unattended-Upgrade "0";`)) {
		t.Error("expected disabled for \"0\"")
	}
}

func TestNftablesHasRules(t *testing.T) {
	if !nftablesHasRules([]byte("table inet filter {\n}\n")) {
		t.Error("expected table detected")
	}
	if nftablesHasRules([]byte("# just a comment\nflush ruleset\n")) {
		t.Error("no table line => false")
	}
}
