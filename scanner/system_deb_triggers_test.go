package scanner

import "testing"

// --- Finding 2: dpkg triggers-awaited / triggers-pending are installed ------

// isInstalledState is the unit under test: "installed", "triggers-awaited" and
// "triggers-pending" all mean the package files are on disk; everything else
// (config-files, not-installed, half-installed, …) is excluded.
func TestIsInstalledState(t *testing.T) {
	cases := []struct {
		status string
		want   bool
	}{
		{"install ok installed", true},
		{"install ok triggers-awaited", true},
		{"install ok triggers-pending", true},
		{"deinstall ok config-files", false},
		{"purge ok not-installed", false},
		{"install ok half-installed", false},
		{"install ok half-configured", false},
		// "unpacked" has all files extracted to disk (only postinst/config
		// pending) → present and CVE-relevant, so it IS installed.
		{"install ok unpacked", true},
		{"", false},
	}
	for _, c := range cases {
		if got := isInstalledState(c.status); got != c.want {
			t.Errorf("isInstalledState(%q) = %v, want %v", c.status, got, c.want)
		}
	}
}

// debStatusTriggersFixture exercises the full status-file parse path: two
// trigger states (files present, awaiting deferred trigger processing) must be
// emitted, while a removed-but-not-purged stanza must stay excluded.
const debStatusTriggersFixture = `Package: python3-awaited
Version: 1.0.0
Status: install ok triggers-awaited

Package: python3-pending
Version: 2.0.0
Status: install ok triggers-pending

Package: python3-normal
Version: 3.0.0
Status: install ok installed

Package: python3-removed
Version: 4.0.0
Status: deinstall ok config-files
`

func TestScanDebianViaStatusFile_EmitsTriggerStates(t *testing.T) {
	t.Setenv("SENTARI_SCAN_OS_PACKAGES", "python_only")
	setDpkgStatusPath(t, debStatusTriggersFixture)

	pkgs, errs := scanDebianViaStatusFile()
	if len(errs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", errs)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}

	for _, name := range []string{"python3-awaited", "python3-pending", "python3-normal"} {
		if _, ok := got[name]; !ok {
			t.Errorf("expected %q (installed / trigger state) to be emitted, got %v", name, keysOf(got))
		}
	}
	if _, ok := got["python3-removed"]; ok {
		t.Errorf("removed-but-not-purged python3-removed must NOT be emitted (got %+v)", got)
	}
}

// debStatusUnpackedFixture exercises the "unpacked" state (files on disk,
// only postinst/config pending) alongside the genuinely-incomplete states
// that must still be excluded.
const debStatusUnpackedFixture = `Package: python3-unpacked
Version: 1.0.0
Status: install ok unpacked

Package: python3-halfinstalled
Version: 2.0.0
Status: install ok half-installed

Package: python3-halfconfigured
Version: 3.0.0
Status: install ok half-configured

Package: python3-configfiles
Version: 4.0.0
Status: deinstall ok config-files
`

func TestScanDebianViaStatusFile_EmitsUnpackedState(t *testing.T) {
	t.Setenv("SENTARI_SCAN_OS_PACKAGES", "python_only")
	setDpkgStatusPath(t, debStatusUnpackedFixture)

	pkgs, errs := scanDebianViaStatusFile()
	if len(errs) != 0 {
		t.Fatalf("unexpected scan errors: %+v", errs)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}

	if _, ok := got["python3-unpacked"]; !ok {
		t.Errorf("expected python3-unpacked (files on disk) to be emitted, got %v", keysOf(got))
	}
	for _, name := range []string{"python3-halfinstalled", "python3-halfconfigured", "python3-configfiles"} {
		if _, ok := got[name]; ok {
			t.Errorf("incomplete/removed %q must NOT be emitted (got %+v)", name, got)
		}
	}
}
