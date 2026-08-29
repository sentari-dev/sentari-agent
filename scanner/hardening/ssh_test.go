package hardening

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCollectSSH_Fixture exercises the real testdata sshd_config + its
// Include glob (sshd_config.d/*.conf) and pins every honesty semantic:
//   - Include expansion + first-obtained-wins across main + included files
//   - a keyword set only inside a Match block  => conditional (unknown)
//   - an unset keyword                          => "(default)" + default_assumed
//   - source_sha256 == sha256 of the file the value came from
func TestCollectSSH_Fixture(t *testing.T) {
	main := filepath.Join("testdata", "ssh", "sshd_config")
	obs := collectSSH(main)

	mainBytes, err := os.ReadFile(main)
	if err != nil {
		t.Fatal(err)
	}
	mainSHA := sha256Hex(mainBytes)
	incBytes, err := os.ReadFile(filepath.Join("testdata", "ssh", "sshd_config.d", "10-crypto.conf"))
	if err != nil {
		t.Fatal(err)
	}
	incSHA := sha256Hex(incBytes)

	// Values set in the MAIN config.
	root := mustObs(t, obs, "ssh.permit_root_login")
	assertValue(t, root, "prohibit-password")
	if root.SourceSHA256 == nil || *root.SourceSHA256 != mainSHA {
		t.Errorf("permit_root_login sha=%v, want main sha %s", root.SourceSHA256, mainSHA)
	}

	// PasswordAuthentication is "no" globally in main; the Match block sets
	// "yes" but first-obtained-wins keeps the global "no".
	assertValue(t, mustObs(t, obs, "ssh.password_authentication"), "no")
	assertValue(t, mustObs(t, obs, "ssh.x11_forwarding"), "yes")
	assertValue(t, mustObs(t, obs, "ssh.max_auth_tries"), "4")

	// Values set only in the INCLUDED file (glob expansion) — provenance points
	// at the include and carries the include's sha256.
	ciph := mustObs(t, obs, "ssh.ciphers")
	assertValue(t, ciph, "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com")
	if ciph.SourcePath == nil || filepath.Base(*ciph.SourcePath) != "10-crypto.conf" {
		t.Errorf("ciphers source_path=%v, want the included file", ciph.SourcePath)
	}
	if ciph.SourceSHA256 == nil || *ciph.SourceSHA256 != incSHA {
		t.Errorf("ciphers sha=%v, want include sha %s", ciph.SourceSHA256, incSHA)
	}
	assertValue(t, mustObs(t, obs, "ssh.permit_empty_passwords"), "no")
	assertValue(t, mustObs(t, obs, "ssh.client_alive_interval"), "300")

	// Unset keywords => documented "(default)" sentinel + default_assumed=true,
	// sourced at the main config.
	for _, slug := range []string{"ssh.macs", "ssh.kex_algorithms", "ssh.protocol", "ssh.login_grace_time"} {
		o := mustObs(t, obs, slug)
		assertValue(t, o, "(default)")
		if !o.DefaultAssumed {
			t.Errorf("%s: default_assumed=false, want true", slug)
		}
	}

	// One observation per known keyword, no more.
	if len(obs) != len(sshKeywords) {
		t.Fatalf("emitted %d observations, want %d (one per keyword)", len(obs), len(sshKeywords))
	}
}

// TestCollectSSH_MatchOnlyIsConditional pins the Match-block honesty case: a
// keyword present ONLY inside a Match block is emitted as unknown with the
// exact "conditional (Match block)" reason, never as a value.
func TestCollectSSH_MatchOnlyIsConditional(t *testing.T) {
	dir := t.TempDir()
	main := writeTemp(t, dir, "sshd_config", `
PermitRootLogin no
Match User bob
    MaxAuthTries 2
    Protocol 1
Match all
X11Forwarding yes
`)
	obs := collectSSH(main)

	// max_auth_tries + protocol are match-only => conditional unknown.
	assertUnknown(t, mustObs(t, obs, "ssh.max_auth_tries"), "conditional (Match block)")
	assertUnknown(t, mustObs(t, obs, "ssh.protocol"), "conditional (Match block)")
	// permit_root_login is a real global value.
	assertValue(t, mustObs(t, obs, "ssh.permit_root_login"), "no")
	// x11_forwarding appears after `Match all` restored global context => a value.
	assertValue(t, mustObs(t, obs, "ssh.x11_forwarding"), "yes")
}

// TestCollectSSH_IncludeUnderMatchIsConditional covers the nested case: an
// Include reached while inside a Match block inherits the conditional context,
// so every keyword it sets is unknown (parseSSHDStreamNested/markIncludeConditional).
func TestCollectSSH_IncludeUnderMatchIsConditional(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "extra.conf", "Ciphers aes256-gcm@openssh.com\n")
	main := writeTemp(t, dir, "sshd_config", `
Match User bob
    Include extra.conf
`)
	obs := collectSSH(main)
	assertUnknown(t, mustObs(t, obs, "ssh.ciphers"), "conditional (Match block)")
}

// TestCollectSSH_UnreadableMain: if the main config cannot be read, every
// keyword is unknown against it (null value + classified reason).
func TestCollectSSH_UnreadableMain(t *testing.T) {
	obs := collectSSH(filepath.Join(t.TempDir(), "does-not-exist"))
	if len(obs) != len(sshKeywords) {
		t.Fatalf("emitted %d, want %d", len(obs), len(sshKeywords))
	}
	for _, o := range obs {
		assertUnknown(t, o, "not found")
	}
}

func TestSplitSSHDLine(t *testing.T) {
	cases := []struct{ in, wantK, wantV string }{
		{"PermitRootLogin no", "PermitRootLogin", "no"},
		{"Ciphers  aes256-gcm@openssh.com", "Ciphers", "aes256-gcm@openssh.com"},
		{"Protocol=2", "Protocol", "2"},
		{"MaxAuthTries = 4", "MaxAuthTries", "4"},
		{`Banner "quoted value"`, "Banner", "quoted value"},
		{"BareKeyword", "BareKeyword", ""},
	}
	for _, c := range cases {
		k, v := splitSSHDLine(c.in)
		if k != c.wantK || v != c.wantV {
			t.Errorf("splitSSHDLine(%q) = (%q,%q), want (%q,%q)", c.in, k, v, c.wantK, c.wantV)
		}
	}
}

func TestExpandSSHDIncludes(t *testing.T) {
	dir := t.TempDir()
	writeTemp(t, dir, "sshd_config.d/10-a.conf", "")
	writeTemp(t, dir, "sshd_config.d/20-b.conf", "")
	main := filepath.Join(dir, "sshd_config")
	got := expandSSHDIncludes(main, "sshd_config.d/*.conf")
	if len(got) != 2 {
		t.Fatalf("glob matched %d files, want 2: %v", len(got), got)
	}
	// Sorted for determinism.
	if filepath.Base(got[0]) != "10-a.conf" || filepath.Base(got[1]) != "20-b.conf" {
		t.Errorf("include order not deterministic: %v", got)
	}
	// Absolute pattern is honored as-is.
	abs := filepath.Join(dir, "sshd_config.d", "10-a.conf")
	if got := expandSSHDIncludes(main, abs); len(got) != 1 {
		t.Errorf("absolute include pattern matched %d, want 1", len(got))
	}
}

func TestSortedSlugs(t *testing.T) {
	got := sortedSlugs()
	if len(got) != len(sshKeywords) {
		t.Fatalf("sortedSlugs len=%d, want %d", len(got), len(sshKeywords))
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] > got[i] {
			t.Fatalf("sortedSlugs not sorted: %v", got)
		}
	}
}

// TestParseSSHDStream_CycleGuard ensures the visited-set / depth guard prevents
// an Include that references its own file from looping.
func TestParseSSHDStream_CycleGuard(t *testing.T) {
	dir := t.TempDir()
	self := writeTemp(t, dir, "loop.conf", "Include loop.conf\nMaxAuthTries 3\n")
	global := map[string]sshResolved{}
	matchOnly := map[string]bool{}
	visited := map[string]bool{}
	data, _ := os.ReadFile(self)
	parseSSHDStream(self, data, "sha", global, matchOnly, visited, 0)
	if r, ok := global["max_auth_tries"]; !ok || r.value != "3" {
		t.Fatalf("self-include cycle broke parsing: %+v", global)
	}
}
