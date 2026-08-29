package hardening

import (
	"path/filepath"
	"testing"
)

// mountinfoFor builds a minimal /proc/self/mountinfo whose "/" line reports the
// given major:minor as the backing device.
func mountinfoFor(majMin string) string {
	return "25 0 " + majMin + " / / rw,relatime - ext4 /dev/mapper/root rw\n" +
		"26 25 8:1 / /boot rw,relatime - ext2 /dev/sda1 rw\n"
}

// TestCollectDiskEncryption_RootDMLUKS: the dm device backing "/" (matched by
// major:minor from mountinfo) carries a CRYPT-LUKS uuid => root_encrypted=true.
func TestCollectDiskEncryption_RootDMLUKS(t *testing.T) {
	dir := t.TempDir()
	sysBlock := filepath.Join(dir, "block")
	writeTemp(t, sysBlock, "dm-0/dev", "253:0\n")
	writeTemp(t, sysBlock, "dm-0/dm/uuid", "CRYPT-LUKS2-deadbeef-root\n")
	mi := writeTemp(t, dir, "mountinfo", mountinfoFor("253:0"))

	obs := collectDiskEncryption(sysBlock, filepath.Join(dir, "no-crypttab"), mi)
	if len(obs) != 1 {
		t.Fatalf("emitted %d, want 1", len(obs))
	}
	assertValue(t, obs[0], "true")
}

// TestCollectDiskEncryption_UnrelatedEncryptedDataDisk: root sits on a plain
// partition (8:1), while an UNRELATED dm-1 data disk is LUKS-encrypted. The
// collector must NOT fabricate a PASS from the unrelated mapping.
func TestCollectDiskEncryption_UnrelatedEncryptedDataDisk(t *testing.T) {
	dir := t.TempDir()
	sysBlock := filepath.Join(dir, "block")
	// Encrypted DATA disk, not the one backing "/".
	writeTemp(t, sysBlock, "dm-1/dev", "253:1\n")
	writeTemp(t, sysBlock, "dm-1/dm/uuid", "CRYPT-LUKS2-data\n")
	// Root is on 8:1 (a plain partition) — no dm entry matches it.
	mi := writeTemp(t, dir, "mountinfo",
		"25 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n")

	obs := collectDiskEncryption(sysBlock, filepath.Join(dir, "no-crypttab"), mi)
	// sysfs+mountinfo were readable and root is not on any dm-LUKS => false.
	assertValue(t, obs[0], "false")
}

// TestCollectDiskEncryption_RootDMLUKS_ViaSlave: root LV is not itself LUKS but
// its dm slave (the PV) is — LVM-on-LUKS => true.
func TestCollectDiskEncryption_RootDMLUKS_ViaSlave(t *testing.T) {
	dir := t.TempDir()
	sysBlock := filepath.Join(dir, "block")
	writeTemp(t, sysBlock, "dm-2/dev", "253:2\n")
	writeTemp(t, sysBlock, "dm-2/dm/uuid", "LVM-abcd-root\n")
	writeTemp(t, sysBlock, "dm-2/slaves/dm-0/.keep", "")
	writeTemp(t, sysBlock, "dm-0/dm/uuid", "CRYPT-LUKS2-pv\n")
	mi := writeTemp(t, dir, "mountinfo", mountinfoFor("253:2"))

	obs := collectDiskEncryption(sysBlock, filepath.Join(dir, "no-crypttab"), mi)
	assertValue(t, obs[0], "true")
}

// TestCollectDiskEncryption_CrypttabRoot: no dm-crypt sysfs mapping, but the
// crypttab fixture declares a "cryptroot" mapping => true, sourced at crypttab.
func TestCollectDiskEncryption_CrypttabRoot(t *testing.T) {
	obs := collectDiskEncryption(
		filepath.Join(t.TempDir(), "no-sysblock"),
		filepath.Join("testdata", "crypttab"),
		filepath.Join(t.TempDir(), "no-mountinfo"),
	)
	if len(obs) != 1 {
		t.Fatalf("emitted %d, want 1", len(obs))
	}
	o := obs[0]
	assertValue(t, o, "true")
	if o.SourcePath == nil || filepath.Base(*o.SourcePath) != "crypttab" {
		t.Errorf("source_path=%v, want crypttab", o.SourcePath)
	}
	if o.SourceSHA256 == nil {
		t.Error("crypttab-sourced true must carry a sha")
	}
}

// TestCollectDiskEncryption_ResolvedNoEncryption: sysfs+mountinfo readable, root
// not on any dm mapping, no crypttab => authoritative false.
func TestCollectDiskEncryption_ResolvedNoEncryption(t *testing.T) {
	dir := t.TempDir()
	sysBlock := filepath.Join(dir, "block")
	writeTemp(t, sysBlock, ".keep", "") // readable, empty
	mi := writeTemp(t, dir, "mountinfo",
		"25 0 8:1 / / rw,relatime - ext4 /dev/sda1 rw\n")

	obs := collectDiskEncryption(sysBlock, filepath.Join(dir, "no-crypttab"), mi)
	assertValue(t, obs[0], "false")
}

// TestCollectDiskEncryption_Unresolved: neither sysfs/mountinfo nor a crypttab
// could be read => honest UNKNOWN, never a false FAIL (5b regression guard).
func TestCollectDiskEncryption_Unresolved(t *testing.T) {
	dir := t.TempDir()
	obs := collectDiskEncryption(
		filepath.Join(dir, "no-sysblock"),
		filepath.Join(dir, "no-crypttab"),
		filepath.Join(dir, "no-mountinfo"),
	)
	if len(obs) != 1 {
		t.Fatalf("emitted %d, want 1", len(obs))
	}
	assertUnknown(t, obs[0], "")
}

// TestCollectDiskEncryption_CrypttabNoRoot: a readable crypttab that maps only a
// non-root volume => false (a successful read of an authoritative source).
func TestCollectDiskEncryption_CrypttabNoRoot(t *testing.T) {
	dir := t.TempDir()
	ct := writeTemp(t, dir, "crypttab", "# comment\nswap /dev/sdb2 /dev/urandom swap\n")
	obs := collectDiskEncryption(filepath.Join(dir, "no-sysblock"), ct, filepath.Join(dir, "no-mountinfo"))
	assertValue(t, obs[0], "false")
}

func TestCrypttabHasEncryptedRoot(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"root name", "root /dev/sda2 none luks", true},
		{"cryptroot", "cryptroot UUID=abcd none luks", true},
		{"luks- prefix", "luks-1234 /dev/sda2 none", true},
		{"contains root", "myroot /dev/sda2 none", true},
		{"swap only", "swap /dev/sdb2 /dev/urandom swap", false},
		{"comment+blank", "# only a comment\n\n", false},
		{"single field", "onlyname", false},
	}
	for _, c := range cases {
		if got := crypttabHasEncryptedRoot([]byte(c.in)); got != c.want {
			t.Errorf("%s: crypttabHasEncryptedRoot=%v, want %v", c.name, got, c.want)
		}
	}
}

// TestRootOnLUKS covers the resolution helper directly.
func TestRootOnLUKS(t *testing.T) {
	dir := t.TempDir()
	sysBlock := filepath.Join(dir, "block")
	writeTemp(t, sysBlock, "dm-0/dev", "253:0\n")
	writeTemp(t, sysBlock, "dm-0/dm/uuid", "CRYPT-LUKS2-deadbeef-root\n")
	// A non-LUKS dm device that also exists but does not back "/".
	writeTemp(t, sysBlock, "dm-9/dev", "253:9\n")
	writeTemp(t, sysBlock, "dm-9/dm/uuid", "LVM-abcd\n")
	mi := writeTemp(t, dir, "mountinfo", mountinfoFor("253:0"))

	luks, src, resolved := rootOnLUKS(sysBlock, mi)
	if !resolved {
		t.Fatal("expected resolved=true")
	}
	if !luks {
		t.Fatal("expected root LUKS mapping to be detected")
	}
	if filepath.Base(filepath.Dir(filepath.Dir(src))) != "dm-0" {
		t.Errorf("discovering path=%q, want under dm-0", src)
	}

	// Unresolvable root (no mountinfo) => resolved=false.
	if _, _, r := rootOnLUKS(sysBlock, filepath.Join(dir, "absent-mi")); r {
		t.Error("absent mountinfo must yield resolved=false")
	}
	// Unreadable sysfs => resolved=false.
	if _, _, r := rootOnLUKS(filepath.Join(dir, "absent-sys"), mi); r {
		t.Error("absent sysfs must yield resolved=false")
	}
}
