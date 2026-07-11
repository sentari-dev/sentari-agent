package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withSystemPkgDBs points the rpm (rpmDbDir) and dpkg (dpkgStatusPath) database
// seams at real, present paths for the duration of a test so the /usr/lib*
// dedup suppression fires — that suppression is gated on the corresponding
// system DB actually existing.  Originals are restored on cleanup.
func withSystemPkgDBs(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	rpmDir := filepath.Join(dir, "rpm")
	if err := os.MkdirAll(rpmDir, 0o755); err != nil {
		t.Fatal(err)
	}
	statusFile := filepath.Join(dir, "dpkg-status")
	if err := os.WriteFile(statusFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	origRpm, origDeb := rpmDbDir, dpkgStatusPath
	rpmDbDir, dpkgStatusPath = rpmDir, statusFile
	t.Cleanup(func() {
		rpmDbDir, dpkgStatusPath = origRpm, origDeb
	})
}

// withoutSystemPkgDBs points both DB seams at nonexistent paths so a
// non-Debian/non-rpm distro (Arch, Gentoo, Void, Alpine) is simulated:
// /usr/lib* site-/dist-packages must then be EMITTED, not suppressed, because
// no system-package scanner would otherwise surface them.
func withoutSystemPkgDBs(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	origRpm, origDeb := rpmDbDir, dpkgStatusPath
	rpmDbDir = filepath.Join(dir, "no-rpm")
	dpkgStatusPath = filepath.Join(dir, "no-dpkg-status")
	t.Cleanup(func() {
		rpmDbDir, dpkgStatusPath = origRpm, origDeb
	})
}

// --- Finding 1: Debian/Ubuntu dist-packages support ------------------------

// pipScanner.Match must claim the "dist-packages" basename so `sudo pip3
// install` packages under /usr/local/lib/pythonX.Y/dist-packages are scanned.
func TestPipMatchClaimsDistPackages(t *testing.T) {
	cases := []struct {
		path string
		base string
	}{
		{"/usr/local/lib/python3.11/dist-packages", "dist-packages"},
		{"/opt/app/lib/python3.12/dist-packages", "dist-packages"},
		{"/home/dev/env/lib/python3.10/site-packages", "site-packages"},
	}
	for _, c := range cases {
		res := pipScanner{}.Match(c.path, c.base)
		if !res.Matched {
			t.Errorf("Match(%q, %q): expected Matched=true", c.path, c.base)
		}
		if res.Env.EnvType != EnvPip || res.Env.Path != c.path {
			t.Errorf("Match(%q): got Env=%+v, want EnvPip at path", c.path, res.Env)
		}
		if !res.Terminal {
			t.Errorf("Match(%q): expected Terminal=true", c.path)
		}
	}
}

// The /usr/lib system dist-packages tree is apt-managed and already reported by
// the dpkg scanner, so the pip scanner must suppress it (claim terminal, emit
// nothing).  /usr/local/lib/... must NOT be suppressed.
func TestPipMatchSuppressesSystemAptDistPackages(t *testing.T) {
	withSystemPkgDBs(t) // dedup only fires when the dpkg DB is present
	suppressed := []string{
		"/usr/lib/python3/dist-packages",
		"/usr/lib/python3.11/dist-packages",
	}
	for _, p := range suppressed {
		res := pipScanner{}.Match(p, "dist-packages")
		if res.Matched {
			t.Errorf("Match(%q): apt path must NOT be emitted (Matched=true)", p)
		}
		if !res.Terminal {
			t.Errorf("Match(%q): apt path should still be Terminal (no descent)", p)
		}
	}

	// /usr/local is a `sudo pip3 install` target dpkg never sees — must match.
	res := pipScanner{}.Match("/usr/local/lib/python3.11/dist-packages", "dist-packages")
	if !res.Matched {
		t.Errorf("/usr/local dist-packages must be emitted (Matched=true)")
	}
}

func TestIsSystemAptDistPackages(t *testing.T) {
	withSystemPkgDBs(t) // path-prefix classification only applies when dpkg DB present
	cases := []struct {
		path string
		want bool
	}{
		{"/usr/lib/python3/dist-packages", true},
		{"/usr/lib/python3.11/dist-packages", true},
		{"/usr/local/lib/python3.11/dist-packages", false},
		{"/home/dev/.venv/lib/python3.12/site-packages", false},
		{"/opt/app/lib/python3.10/dist-packages", false},
	}
	for _, c := range cases {
		if got := isSystemAptDistPackages(c.path); got != c.want {
			t.Errorf("isSystemAptDistPackages(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// scanPipEnvironment must locate a dist-packages leaf (Debian layout) and
// parse the packages inside it, exactly as it does for site-packages.
func TestScanPipEnvironmentFindsDistPackages(t *testing.T) {
	envDir := t.TempDir()
	distPackages := filepath.Join(envDir, "lib", "python3.11", "dist-packages")
	if err := os.MkdirAll(distPackages, 0o755); err != nil {
		t.Fatal(err)
	}
	distInfo := filepath.Join(distPackages, "requests-2.31.0.dist-info")
	if err := os.MkdirAll(distInfo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(distInfo, "METADATA"),
		[]byte("Name: requests\nVersion: 2.31.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	pkgs, errs := scanPipEnvironment(envDir)
	if len(errs) != 0 {
		t.Fatalf("unexpected errors: %+v", errs)
	}
	found := false
	for _, p := range pkgs {
		if p.Name == "requests" && p.Version == "2.31.0" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected requests@2.31.0 from dist-packages, got %+v", pkgs)
	}
}

// findSitePackages must resolve both a passed-in dist-packages leaf and a
// dist-packages leaf nested under lib/pythonX.Y.
func TestFindSitePackagesDistPackages(t *testing.T) {
	// Leaf passed directly (the Match→Scan common case).
	leaf := filepath.Join(t.TempDir(), "dist-packages")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := findSitePackages(leaf); got != leaf {
		t.Errorf("findSitePackages(leaf) = %q, want %q", got, leaf)
	}

	// Nested under lib/pythonX.Y.
	env := t.TempDir()
	nested := filepath.Join(env, "lib", "python3.12", "dist-packages")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := findSitePackages(env); got != nested {
		t.Errorf("findSitePackages(env) = %q, want %q", got, nested)
	}
}

// --- Finding scanner-1: RHEL/Fedora system site-packages suppression -------

// pipScanner.Match must suppress RPM-owned site-packages under /usr/lib and
// /usr/lib64 (the rpm scanner already reports those under python3-<name>
// coordinates) while keeping /usr/local/lib/.../site-packages (sudo-pip)
// visible — the RPM mirror of the Debian dist-packages dedup.
func TestPipMatchSuppressesSystemRpmSitePackages(t *testing.T) {
	withSystemPkgDBs(t) // dedup only fires when the rpm DB is present
	suppressed := []string{
		"/usr/lib/python3.9/site-packages",
		"/usr/lib64/python3.9/site-packages",
		"/usr/lib/python3.11/site-packages",
		"/usr/lib64/python3.11/site-packages",
	}
	for _, p := range suppressed {
		res := pipScanner{}.Match(p, "site-packages")
		if res.Matched {
			t.Errorf("Match(%q): rpm system path must NOT be emitted (Matched=true)", p)
		}
		if !res.Terminal {
			t.Errorf("Match(%q): rpm system path should still be Terminal (no descent)", p)
		}
	}

	// /usr/local is a `sudo pip install` target rpm never sees — must match.
	kept := []string{
		"/usr/local/lib/python3.9/site-packages",
		"/usr/local/lib64/python3.9/site-packages",
	}
	for _, p := range kept {
		res := pipScanner{}.Match(p, "site-packages")
		if !res.Matched {
			t.Errorf("Match(%q): /usr/local site-packages must be emitted (Matched=true)", p)
		}
		if res.Env.EnvType != EnvPip || res.Env.Path != p {
			t.Errorf("Match(%q): got Env=%+v, want EnvPip at path", p, res.Env)
		}
	}
}

func TestIsSystemRpmSitePackages(t *testing.T) {
	withSystemPkgDBs(t) // path-prefix classification only applies when rpm DB present
	cases := []struct {
		path string
		want bool
	}{
		{"/usr/lib/python3.9/site-packages", true},
		{"/usr/lib64/python3.9/site-packages", true},
		{"/usr/lib/python3.11/site-packages", true},
		{"/usr/lib64/python3.11/site-packages", true},
		{"/usr/local/lib/python3.9/site-packages", false},
		{"/usr/local/lib64/python3.9/site-packages", false},
		{"/home/dev/.venv/lib/python3.12/site-packages", false},
		{"/opt/app/lib/python3.10/site-packages", false},
	}
	for _, c := range cases {
		if got := isSystemRpmSitePackages(c.path); got != c.want {
			t.Errorf("isSystemRpmSitePackages(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}

// --- Finding scanner-3: dedup suppression gated on system DB presence ------

// On a non-rpm/non-dpkg distro the corresponding system-package scanner
// no-ops, so the /usr/lib* dedup MUST NOT fire — otherwise the system
// interpreter's packages appear in no ecosystem at all (silent false-negative).
func TestSystemSitePackagesEmittedWhenNoSystemDb(t *testing.T) {
	withoutSystemPkgDBs(t)

	// rpm classifier: /usr/lib* now surfaces (returns false = not suppressed).
	for _, p := range []string{
		"/usr/lib/python3.9/site-packages",
		"/usr/lib64/python3.11/site-packages",
	} {
		if isSystemRpmSitePackages(p) {
			t.Errorf("isSystemRpmSitePackages(%q) = true with no rpm DB; must be false (emitted)", p)
		}
		res := pipScanner{}.Match(p, "site-packages")
		if !res.Matched {
			t.Errorf("Match(%q) must be emitted (Matched=true) when no rpm DB present", p)
		}
	}

	// apt classifier: /usr/lib dist-packages now surfaces too.
	for _, p := range []string{
		"/usr/lib/python3/dist-packages",
		"/usr/lib/python3.11/dist-packages",
	} {
		if isSystemAptDistPackages(p) {
			t.Errorf("isSystemAptDistPackages(%q) = true with no dpkg DB; must be false (emitted)", p)
		}
		res := pipScanner{}.Match(p, "dist-packages")
		if !res.Matched {
			t.Errorf("Match(%q) must be emitted (Matched=true) when no dpkg DB present", p)
		}
	}
}

// When the system DB IS present (RHEL/Debian), the dedup still fires: /usr/lib*
// is suppressed while /usr/local stays visible.  Guards the RHEL/Debian path
// against a regression from the non-rpm-distro fix.
func TestSystemSitePackagesSuppressedWhenDbPresent(t *testing.T) {
	withSystemPkgDBs(t)

	if !isSystemRpmSitePackages("/usr/lib64/python3.9/site-packages") {
		t.Errorf("rpm /usr/lib64 site-packages must be suppressed when rpm DB present")
	}
	if !isSystemAptDistPackages("/usr/lib/python3/dist-packages") {
		t.Errorf("apt /usr/lib dist-packages must be suppressed when dpkg DB present")
	}
	// /usr/local is a sudo-pip target the system scanners never see — always kept.
	if isSystemRpmSitePackages("/usr/local/lib/python3.9/site-packages") {
		t.Errorf("/usr/local site-packages must never be suppressed")
	}
	if isSystemAptDistPackages("/usr/local/lib/python3.11/dist-packages") {
		t.Errorf("/usr/local dist-packages must never be suppressed")
	}
}

// --- Finding 3: version_info fallback in detectInterpreterVersion ----------

func TestDetectInterpreterVersionVersionInfoFallback(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
		want string
	}{
		{
			// uv / PyPA-virtualenv: only a version_info line, CPython release tag.
			name: "version_info_final_tag",
			cfg:  "home = /usr/bin\nversion_info = 3.12.4.final.0\n",
			want: "3.12.4",
		},
		{
			// uv sometimes writes a plain X.Y.Z version_info.
			name: "version_info_plain",
			cfg:  "home = /usr/bin\nversion_info = 3.11.9\n",
			want: "3.11.9",
		},
		{
			// A clean `version` key always wins over version_info.
			name: "version_key_wins",
			cfg:  "version_info = 3.12.4.final.0\nversion = 3.10.2\n",
			want: "3.10.2",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			env := t.TempDir()
			if err := os.WriteFile(filepath.Join(env, "pyvenv.cfg"),
				[]byte(c.cfg), 0o644); err != nil {
				t.Fatal(err)
			}
			if got := detectInterpreterVersion(env); got != c.want {
				t.Errorf("detectInterpreterVersion() = %q, want %q", got, c.want)
			}
		})
	}
}

// --- Finding scanner-5: >64 KiB METADATA header line must not drop package --

// A dist-info whose METADATA carries a single header line larger than
// bufio.Scanner's default 64 KiB token cap must NOT cause the package to be
// dropped: buffer sizing prevents bufio.ErrTooLong, and the dir-name fallback
// is the safety net for name+version.
func TestParseDistInfoHugeHeaderLineStillEmitted(t *testing.T) {
	env := t.TempDir()
	site := filepath.Join(env, "lib", "python3.11", "site-packages")
	distInfo := filepath.Join(site, "bigpkg-1.2.3.dist-info")
	if err := os.MkdirAll(distInfo, 0o755); err != nil {
		t.Fatal(err)
	}

	// A >64 KiB single Description line folded onto one physical line, with no
	// parseable Name:/Version: header — forcing the dir-name fallback while also
	// exercising the enlarged scanner buffer.
	huge := strings.Repeat("A", 200<<10) // 200 KiB, well over the 64 KiB default cap
	metadata := "Metadata-Version: 2.1\nDescription: " + huge + "\n"
	if err := os.WriteFile(filepath.Join(distInfo, "METADATA"), []byte(metadata), 0o644); err != nil {
		t.Fatal(err)
	}

	pkgs, errs := scanPipEnvironment(env)
	if len(errs) != 0 {
		t.Fatalf("unexpected scan errors (package dropped instead of recovered): %+v", errs)
	}
	var found *PackageRecord
	for i := range pkgs {
		if pkgs[i].Name == "bigpkg" {
			found = &pkgs[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("bigpkg not emitted from a >64 KiB-header METADATA; got %+v", pkgs)
	}
	if found.Version != "1.2.3" {
		t.Errorf("Version = %q, want 1.2.3 (from dir-name fallback)", found.Version)
	}
}

func TestNormalizePyvenvVersionInfo(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"3.12.4", "3.12.4"},
		{"3.12.4.final.0", "3.12.4"},
		{"3.12.4.candidate.1", "3.12.4"},
		{"3.12", "3.12"},
		{"3.12.4.5", "3.12.4.5"}, // 4th component numeric → kept verbatim
	}
	for _, c := range cases {
		if got := normalizePyvenvVersionInfo(c.in); got != c.want {
			t.Errorf("normalizePyvenvVersionInfo(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
