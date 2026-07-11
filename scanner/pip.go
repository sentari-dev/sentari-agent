package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// pipScanner discovers global pip installs by matching site-packages
// directories during the shared walk.  Venvs have their own scanner
// (venvScanner) because they also need dangling-symlink detection and
// a different EnvType tag on emitted packages.
type pipScanner struct{}

func (pipScanner) EnvType() string { return EnvPip }

func (pipScanner) Match(dirPath, base string) MatchResult {
	// Debian/Ubuntu patch CPython to install into "dist-packages" rather than
	// the upstream "site-packages": `sudo pip3 install` lands in
	// /usr/local/lib/pythonX.Y/dist-packages and apt modules in
	// /usr/lib/python3/dist-packages.  Claim both basenames so sudo-pip
	// packages are not invisible on Debian-family hosts.
	if base != "site-packages" && base != "dist-packages" {
		return MatchResult{}
	}
	// Dedup: the /usr/lib system dist-packages tree holds apt-managed modules
	// that the dpkg scanner ALREADY reports under their Debian (python3-<name>)
	// coordinates — emitting them again here as pip records double-counts the
	// same library.  /usr/local/lib/.../dist-packages, by contrast, holds
	// `sudo pip3 install` packages that dpkg never sees and MUST be reported.
	// Claim the dir as terminal (so we don't descend) but emit nothing.
	if base == "dist-packages" && isSystemAptDistPackages(dirPath) {
		return MatchResult{Terminal: true}
	}
	// Mirror image on RPM distros: RHEL/Fedora/SUSE keep the *system*
	// interpreter's packages in site-packages under /usr/lib and /usr/lib64
	// (e.g. /usr/lib/python3.9/site-packages, /usr/lib64/python3.9/site-packages).
	// Those modules are owned by rpm and the rpm scanner ALREADY reports them
	// under their distro (python3-<name>) coordinates — emitting them again as
	// pip records double-counts the same library and, worse, correlates it
	// against upstream PyPI version ranges instead of the release-keyed distro
	// feed (reintroducing the backport false-positive class).  Claim terminal
	// (don't descend) but emit nothing.  /usr/local/lib/.../site-packages is
	// left visible: that is a `sudo pip install` target rpm never sees.
	if base == "site-packages" && isSystemRpmSitePackages(dirPath) {
		return MatchResult{Terminal: true}
	}
	return MatchResult{
		Matched:  true,
		Terminal: true, // don't descend into site-packages itself
		Env: Environment{
			EnvType: EnvPip,
			Path:    dirPath,
			Name:    "global",
		},
	}
}

// rpmDbDir mirrors the /var/lib/rpm existence gate in system_rpm.go's
// rpmScanner.DiscoverAll: the rpm scanner only reports the system
// interpreter's site-packages when this directory is present.  The dpkg
// counterpart, dpkgStatusPath, already exists as a package-level var in
// system_deb.go and is reused directly.  Both are vars (not consts) so
// tests can point them at a TempDir to exercise the present/absent branches.
var rpmDbDir = "/var/lib/rpm"

// systemRpmDbPresent reports whether an rpm package database exists on this
// host (i.e. the rpm scanner would actually surface the system interpreter's
// site-packages).  Gating the dedup suppression on this keeps the fix in
// isSystemRpmSitePackages honest: on a non-rpm distro (Arch, Gentoo, Void,
// Alpine) the rpm scanner no-ops, so suppressing /usr/lib* here would make
// those packages appear in NO ecosystem at all.
func systemRpmDbPresent() bool {
	_, err := os.Stat(rpmDbDir)
	return err == nil
}

// systemDebDbPresent is the dpkg counterpart of systemRpmDbPresent, keyed on
// the same /var/lib/dpkg/status file the dpkg scanner requires (dpkgStatusPath
// in system_deb.go).  On a non-Debian distro the dpkg scanner no-ops, so the
// apt dedup suppression must not fire either.
func systemDebDbPresent() bool {
	_, err := os.Stat(dpkgStatusPath)
	return err == nil
}

// isSystemAptDistPackages reports whether a dist-packages directory is the
// Debian/Ubuntu *system* apt location under /usr/lib (e.g.
// /usr/lib/python3/dist-packages or /usr/lib/python3.11/dist-packages).
// Those modules are owned by apt/dpkg and are already surfaced by the dpkg
// scanner, so the pip scanner suppresses them to avoid double counting.
//
// The suppression is gated on the dpkg status file actually being present:
// on a non-Debian distro the dpkg scanner no-ops, and suppressing here
// unconditionally would make /usr/lib/.../dist-packages packages appear in no
// ecosystem at all (a silent false-negative).  With the DB present, dpkg
// reports them and the dedup holds.
//
// /usr/local/lib/.../dist-packages is deliberately NOT matched: that is where
// `sudo pip3 install` writes, dpkg never sees it, and surfacing it is the
// whole point of claiming the dist-packages basename.
func isSystemAptDistPackages(dirPath string) bool {
	if !systemDebDbPresent() {
		return false
	}
	return strings.HasPrefix(filepath.ToSlash(filepath.Clean(dirPath)), "/usr/lib/")
}

// isSystemRpmSitePackages reports whether a site-packages directory is an
// RPM-distro *system* interpreter location under /usr/lib or /usr/lib64
// (e.g. /usr/lib/python3.9/site-packages or /usr/lib64/python3.9/site-packages
// on RHEL/Fedora, /usr/lib64/pythonX.Y/site-packages on SUSE).  Those modules
// are owned by rpm and already surfaced by the rpm scanner, so the pip scanner
// suppresses them to avoid double counting — the RPM mirror of
// isSystemAptDistPackages.
//
// The suppression is gated on the rpm database (/var/lib/rpm) actually being
// present: on a non-rpm distro (Arch, Gentoo, Void, Alpine — all runnable by
// the static agent) the rpm scanner no-ops, and suppressing here
// unconditionally would make the system interpreter's /usr/lib* packages
// appear in no ecosystem at all.  With the DB present, rpm reports them and
// the dedup holds.
//
// /usr/local/lib/.../site-packages is deliberately NOT matched: that is where
// `sudo pip install` writes, rpm never sees it, and surfacing it is the whole
// point of claiming the site-packages basename.
func isSystemRpmSitePackages(dirPath string) bool {
	if !systemRpmDbPresent() {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(dirPath))
	return strings.HasPrefix(clean, "/usr/lib/") || strings.HasPrefix(clean, "/usr/lib64/")
}

func (pipScanner) Scan(_ context.Context, env Environment) ([]PackageRecord, []ScanError) {
	return scanPipEnvironment(env.Path)
}

// venvScanner discovers virtualenvs by matching pyvenv.cfg and rejects
// dangling venvs (whose base interpreter has been uninstalled) with a
// warning instead of queueing them.  Venv-tagged packages share the pip
// parser but are re-tagged with EnvVenv in Scan().
type venvScanner struct{}

func (venvScanner) EnvType() string { return EnvVenv }

func (venvScanner) Match(dirPath, base string) MatchResult {
	pyvenvCfg := filepath.Join(dirPath, "pyvenv.cfg")
	// Lstat (not Stat) so we don't follow a symlinked marker: a hostile
	// directory could plant `pyvenv.cfg -> /some/real/file` to make an
	// arbitrary directory look like a venv (audit finding 6).  A genuine
	// venv always has a regular-file pyvenv.cfg.
	info, err := os.Lstat(pyvenvCfg)
	if err != nil {
		return MatchResult{}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return MatchResult{}
	}
	if reason := isVenvDangling(dirPath, pyvenvCfg); reason != "" {
		return MatchResult{
			Terminal: true,
			Warning: &ScanError{
				Path:      dirPath,
				EnvType:   EnvVenv,
				Error:     reason,
				Timestamp: time.Now().UTC(),
			},
		}
	}
	return MatchResult{
		Matched:  true,
		Terminal: true, // don't descend into a venv
		Env: Environment{
			EnvType: EnvVenv,
			Path:    dirPath,
			Name:    base,
		},
	}
}

func (venvScanner) Scan(_ context.Context, env Environment) ([]PackageRecord, []ScanError) {
	pkgs, errs := scanPipEnvironment(env.Path)
	// scanPipEnvironment tags every record as EnvPip; override to EnvVenv
	// (or EnvUv for uv-managed venvs) so the server distinguishes global pip
	// from venv-scoped packages and emits the right remediation command — a
	// plain `pip install` into a uv project is reverted by `uv sync`.
	envType := EnvVenv
	if isUvVenv(filepath.Join(env.Path, "pyvenv.cfg")) {
		envType = EnvUv
	}
	for i := range pkgs {
		pkgs[i].EnvType = envType
	}
	return pkgs, errs
}

// isUvVenv reports whether a venv's pyvenv.cfg was written by uv.  uv records
// its own version in the venv config as a `uv = X.Y.Z` line; CPython's
// venv/virtualenv never write that key.  Read via safeio (symlink-refusing,
// size-capped) for the same reason the rest of the scanner does.
func isUvVenv(pyvenvCfgPath string) bool {
	data, err := safeio.ReadFile(pyvenvCfgPath, maxPyvenvCfgSize)
	if err != nil {
		return false
	}
	s := bufio.NewScanner(bytes.NewReader(data))
	for s.Scan() {
		key, _, found := strings.Cut(s.Text(), "=")
		if found && strings.TrimSpace(key) == "uv" {
			return true
		}
	}
	return false
}

func init() {
	Register(pipScanner{})
	Register(venvScanner{})
}

// scanPipEnvironment scans a pip/venv environment for installed packages
// by parsing .dist-info/METADATA and .egg-info/PKG-INFO files.
func scanPipEnvironment(envPath string) ([]PackageRecord, []ScanError) {
	var packages []PackageRecord
	var scanErrs []ScanError

	// Locate the site-packages directory.
	sitePackagesPath := findSitePackages(envPath)
	if sitePackagesPath == "" {
		scanErrs = append(scanErrs, ScanError{
			Path:      envPath,
			EnvType:   EnvPip,
			Error:     "site-packages not found",
			Timestamp: time.Now().UTC(),
		})
		return packages, scanErrs
	}

	entries, err := os.ReadDir(sitePackagesPath)
	if err != nil {
		scanErrs = append(scanErrs, ScanError{
			Path:      sitePackagesPath,
			EnvType:   EnvPip,
			Error:     err.Error(),
			Timestamp: time.Now().UTC(),
		})
		return packages, scanErrs
	}

	for _, entry := range entries {
		name := entry.Name()

		if entry.IsDir() {
			if strings.HasSuffix(name, ".dist-info") {
				pkg, err := parseDistInfo(filepath.Join(sitePackagesPath, name), envPath)
				if err == nil {
					packages = append(packages, pkg)
				} else {
					scanErrs = append(scanErrs, ScanError{
						Path:      filepath.Join(sitePackagesPath, name),
						EnvType:   EnvPip,
						Error:     err.Error(),
						Timestamp: time.Now().UTC(),
					})
				}
				continue
			}

			if strings.HasSuffix(name, ".egg-info") {
				pkg, err := parseEggInfo(filepath.Join(sitePackagesPath, name), envPath)
				if err == nil {
					packages = append(packages, pkg)
				} else {
					scanErrs = append(scanErrs, ScanError{
						Path:      filepath.Join(sitePackagesPath, name),
						EnvType:   EnvPip,
						Error:     err.Error(),
						Timestamp: time.Now().UTC(),
					})
				}
			}
			continue
		}

		// .egg-link files are regular files (not directories) created by
		// legacy editable installs (pip install -e with older setuptools).
		if strings.HasSuffix(name, ".egg-link") {
			pkg, err := parseEggLink(filepath.Join(sitePackagesPath, name), sitePackagesPath)
			if err == nil {
				packages = append(packages, pkg)
			} else {
				scanErrs = append(scanErrs, ScanError{
					Path:      filepath.Join(sitePackagesPath, name),
					EnvType:   EnvPip,
					Error:     err.Error(),
					Timestamp: time.Now().UTC(),
				})
			}
		}
	}

	// Determine interpreter version from filesystem (never invoke python binary).
	interpreterVersion := detectInterpreterVersion(envPath)

	for i := range packages {
		packages[i].EnvType = EnvPip
		packages[i].Environment = envPath
		packages[i].InterpreterVersion = interpreterVersion
	}

	return packages, scanErrs
}

// findSitePackages locates the site-packages directory inside an environment.
// It handles both Unix (lib/pythonX.Y/site-packages) and Windows
// (Lib/site-packages).  On Debian/Ubuntu, CPython is patched to use
// "dist-packages" instead of "site-packages", so those leaves are probed too
// (see pipScanner.Match).
func findSitePackages(envPath string) string {
	// If the path itself IS a site-packages / dist-packages dir, use it
	// directly — this is the common case: Match() hands the leaf dir straight
	// to Scan().
	if base := filepath.Base(envPath); base == "site-packages" || base == "dist-packages" {
		return envPath
	}

	// Unix layout: lib/pythonX.Y/{site,dist}-packages
	libDir := filepath.Join(envPath, "lib")
	if entries, err := os.ReadDir(libDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), "python") {
				for _, leaf := range []string{"site-packages", "dist-packages"} {
					candidate := filepath.Join(libDir, entry.Name(), leaf)
					if info, err := os.Stat(candidate); err == nil && info.IsDir() {
						return candidate
					}
				}
			}
		}
	}

	// Windows layout: Lib/site-packages
	candidate := filepath.Join(envPath, "Lib", "site-packages")
	if info, err := os.Stat(candidate); err == nil && info.IsDir() {
		return candidate
	}

	return ""
}

// detectInterpreterVersion determines the Python version without invoking any binary.
// It reads pyvenv.cfg (contains "version = 3.11.0") or infers from the
// lib/pythonX.Y directory name.
func detectInterpreterVersion(envPath string) string {
	// Strategy 1: Parse pyvenv.cfg — most reliable for venvs.
	// Read the whole file via safeio (symlink-refusing, size-capped)
	// then scan it in memory; a plain os.Open would silently follow
	// a pyvenv.cfg -> /etc/shadow symlink planted by an unprivileged
	// user inside a venv directory they control.
	pyvenvCfg := filepath.Join(envPath, "pyvenv.cfg")
	if data, err := safeio.ReadFile(pyvenvCfg, maxPyvenvCfgSize); err == nil {
		var versionInfo string
		s := bufio.NewScanner(bytes.NewReader(data))
		for s.Scan() {
			key, val, found := strings.Cut(s.Text(), "=")
			if !found {
				continue
			}
			// Match the key EXACTLY.  A prefix test on "version" would wrongly
			// capture the "version_info" line CPython 3.11+ also writes.
			switch strings.TrimSpace(key) {
			case "version":
				// The clean `version = 3.11.0` key always wins.
				if v := strings.TrimSpace(val); v != "" {
					return v
				}
			case "version_info":
				// Fallback: uv- and PyPA-virtualenv-created venvs write ONLY a
				// `version_info = 3.11.0.final.0` line (no plain `version`),
				// so the pip scanner previously reported no interpreter version
				// for them while the runtime detector found it.  Mirror the
				// fallback + release-tag normalisation of parsePyvenvVersion in
				// scanner/runtimeversions/python.go — that helper is unexported
				// in a sibling package, so the small logic is duplicated here
				// rather than shared.
				versionInfo = strings.TrimSpace(val)
			}
		}
		if v := normalizePyvenvVersionInfo(versionInfo); v != "" {
			return v
		}
	}

	// Strategy 2: Infer from lib/pythonX.Y directory name.
	libDir := filepath.Join(envPath, "lib")
	if entries, err := os.ReadDir(libDir); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() && strings.HasPrefix(name, "python") {
				// "python3.11" → "3.11"
				ver := strings.TrimPrefix(name, "python")
				if ver != "" {
					return ver
				}
			}
		}
	}

	// Strategy 3: Check for python version file in Windows Lib directory.
	libDir = filepath.Join(envPath, "Lib")
	if entries, err := os.ReadDir(libDir); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() && strings.HasPrefix(name, "python") {
				return strings.TrimPrefix(name, "python")
			}
		}
	}

	return "unknown"
}

// parseDistInfo parses METADATA file from a .dist-info directory.
// The METADATA file is an RFC 822-style file with Name: and Version:
// headers.  Read via safeio — a malicious site-packages entry that
// planted a METADATA symlink to /etc/shadow would otherwise end up in
// the scan payload we upload.  We read once and scan the bytes in-
// memory for both header extraction and license parsing.
func parseDistInfo(distInfoPath, envPath string) (PackageRecord, error) {
	metadataPath := filepath.Join(distInfoPath, "METADATA")
	data, err := safeio.ReadFile(metadataPath, maxPipMetadataSize)
	if err != nil {
		return PackageRecord{}, err
	}

	pkg := PackageRecord{
		InstallPath:   distInfoPath,
		InstallDate:   getFileModTime(distInfoPath),
		InstallerUser: getInstallerUser(distInfoPath),
	}

	s := bufio.NewScanner(bytes.NewReader(data))
	// A single METADATA header line can exceed bufio.Scanner's default 64 KiB
	// token cap — e.g. a huge Description or Classifier field folded onto one
	// physical line.  Without a larger buffer that trips bufio.ErrTooLong and
	// (pre-fix) dropped the whole package.  Size the buffer to the same cap the
	// safeio read is bounded by (maxPipMetadataSize) so no in-file line can
	// overflow it — mirroring the system_deb round-4 fix.
	s.Buffer(make([]byte, 0, 64<<10), int(maxPipMetadataSize))
	for s.Scan() {
		line := s.Text()

		if strings.HasPrefix(line, "Name: ") {
			pkg.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name: "))
		} else if strings.HasPrefix(line, "Version: ") {
			pkg.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
		}

		// Once we have both, no need to read further.
		if pkg.Name != "" && pkg.Version != "" {
			break
		}

		// METADATA headers end at the first blank line — stop early.
		if line == "" {
			break
		}
	}

	// A scan error (e.g. a pathological line larger than the buffer cap) must
	// NOT drop the package: fall through to the dist-info dir-name fallback
	// below, which still recovers name+version.  Buffer sizing above makes this
	// path effectively unreachable for in-file lines; the fallback is the
	// safety net.
	_ = s.Err()

	// Fallback: extract name from directory name if METADATA is incomplete.
	if pkg.Name == "" {
		base := filepath.Base(distInfoPath)
		base = strings.TrimSuffix(base, ".dist-info")
		if idx := strings.LastIndex(base, "-"); idx > 0 {
			pkg.Name = base[:idx]
			if pkg.Version == "" {
				pkg.Version = base[idx+1:]
			}
		} else {
			pkg.Name = base
		}
	}

	// Extract license info from the same bytes we already have.
	raw, spdx, tier := ExtractLicenseFromMetadata(string(data))
	pkg.LicenseRaw = raw
	pkg.LicenseSPDX = spdx
	pkg.LicenseTier = tier

	return pkg, nil
}

// parseEggInfo parses PKG-INFO file from a .egg-info directory.
// Same safeio treatment as parseDistInfo — single read, scan bytes
// in-memory for both header and license extraction.
func parseEggInfo(eggInfoPath, envPath string) (PackageRecord, error) {
	pkgInfoPath := filepath.Join(eggInfoPath, "PKG-INFO")
	data, err := safeio.ReadFile(pkgInfoPath, maxPipMetadataSize)
	if err != nil {
		return PackageRecord{}, err
	}

	pkg := PackageRecord{
		InstallPath:   eggInfoPath,
		InstallDate:   getFileModTime(eggInfoPath),
		InstallerUser: getInstallerUser(eggInfoPath),
	}

	s := bufio.NewScanner(bytes.NewReader(data))
	// Same >64 KiB single-header-line guard as parseDistInfo: size the buffer to
	// the read cap so a folded Description/Classifier line does not trip
	// bufio.ErrTooLong and drop the package.
	s.Buffer(make([]byte, 0, 64<<10), int(maxPipMetadataSize))
	for s.Scan() {
		line := s.Text()

		if strings.HasPrefix(line, "Name: ") {
			pkg.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name: "))
		} else if strings.HasPrefix(line, "Version: ") {
			pkg.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
		}

		if pkg.Name != "" && pkg.Version != "" {
			break
		}

		if line == "" {
			break
		}
	}

	// Do not drop the package on a scan error — fall through to the .egg-info
	// dir-name fallback below (buffer sizing already prevents the error for
	// in-file lines).
	_ = s.Err()

	if pkg.Name == "" {
		base := filepath.Base(eggInfoPath)
		base = strings.TrimSuffix(base, ".egg-info")
		if idx := strings.LastIndex(base, "-"); idx > 0 {
			pkg.Name = base[:idx]
			if pkg.Version == "" {
				pkg.Version = base[idx+1:]
			}
		} else {
			pkg.Name = base
		}
	}

	// Extract license info from the bytes we already have.
	{
		raw, spdx, tier := ExtractLicenseFromMetadata(string(data))
		pkg.LicenseRaw = raw
		pkg.LicenseSPDX = spdx
		pkg.LicenseTier = tier
	}

	return pkg, nil
}

// parseEggLink parses a legacy .egg-link file from site-packages.
// An egg-link is a plain text file where the first line is the path to the
// source directory of an editable install (pip install -e). The package name
// is extracted from the filename, and the version from PKG-INFO in the linked
// source directory if available.
func parseEggLink(eggLinkPath, sitePackagesPath string) (PackageRecord, error) {
	data, err := safeio.ReadFile(eggLinkPath, maxEggLinkSize)
	if err != nil {
		return PackageRecord{}, err
	}

	lines := strings.SplitN(strings.TrimSpace(string(data)), "\n", 2)
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return PackageRecord{}, fmt.Errorf("empty egg-link file: %s", eggLinkPath)
	}

	srcDir := strings.TrimSpace(lines[0])
	// egg-link paths may be relative to site-packages.
	if !filepath.IsAbs(srcDir) {
		srcDir = filepath.Join(sitePackagesPath, srcDir)
	}

	// Extract package name from filename: my-project.egg-link -> my-project
	baseName := filepath.Base(eggLinkPath)
	pkgName := strings.TrimSuffix(baseName, ".egg-link")

	pkg := PackageRecord{
		Name:        pkgName,
		Version:     "unknown",
		InstallPath: srcDir,
		InstallDate: getFileModTime(eggLinkPath),
	}

	// Try to find version from PKG-INFO in an .egg-info dir inside srcDir.
	if entries, err := os.ReadDir(srcDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && strings.HasSuffix(entry.Name(), ".egg-info") {
				if parsed, err := parseEggInfo(filepath.Join(srcDir, entry.Name()), sitePackagesPath); err == nil {
					pkg.Name = parsed.Name
					pkg.Version = parsed.Version
				}
				break
			}
		}
	}

	return pkg, nil
}

// normalizePyvenvVersionInfo turns a pyvenv.cfg `version_info` value into a
// clean X.Y.Z string.  CPython writes `3.12.4.final.0`; uv and virtualenv write
// a plain `3.12.4`.  When more than three dot-separated components are present
// and the 4th is a non-numeric release-level tag (`final`, `candidate`, …) we
// keep only the first three so server EOL correlation sees `3.12.4`.  Mirrors
// normalizeVersionInfo in scanner/runtimeversions/python.go (unexported there).
func normalizePyvenvVersionInfo(v string) string {
	if v == "" {
		return ""
	}
	parts := strings.Split(v, ".")
	if len(parts) > 3 && !allDigits(parts[3]) {
		return strings.Join(parts[:3], ".")
	}
	return v
}

// allDigits reports whether s is non-empty and entirely ASCII digits.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// getFileModTime returns the modification time of a file as an RFC 3339 string.
func getFileModTime(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return info.ModTime().UTC().Format(time.RFC3339)
}

// getInstallerUser returns the OS owner of the file at the given path.
// Delegates to the platform-specific getFileOwner in owner_{unix,windows}.go.
func getInstallerUser(path string) string {
	return getFileOwner(path)
}
