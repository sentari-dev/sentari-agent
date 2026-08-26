package scanner

import (
	"bufio"
	"context"
	stderrors "errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// dpkgStatusPath is the dpkg status file location.  Declared as a var
// (not a const) so tests can point it at a TempDir to exercise
// SENTARI_SCAN_OS_PACKAGES=all / "python_only" without needing a real
// Debian host.
var dpkgStatusPath = "/var/lib/dpkg/status"

// debScanner discovers system-installed Python packages on Debian/Ubuntu
// by reading /var/lib/dpkg/status directly.  It's a RootScanner because
// the dpkg database is a single fixed file, not something the walker
// would find by pattern-matching directories.
type debScanner struct{}

func (debScanner) EnvType() string { return EnvSystemDeb }

func (debScanner) DiscoverAll(ctx context.Context) ([]Environment, []ScanError) {
	if runtime.GOOS != "linux" {
		return nil, nil
	}
	// Gate on full-system scan: a scoped run under /opt/app or a tempdir
	// shouldn't inherit every system-wide Python package from dpkg.
	if !IsFullSystemScan(ctx) {
		return nil, nil
	}
	if _, err := os.Stat(dpkgStatusPath); err != nil {
		return nil, nil // dpkg absent → not a Debian-family host
	}
	return []Environment{{
		EnvType: EnvSystemDeb,
		Path:    "/var/lib/dpkg",
		Name:    "dpkg",
	}}, nil
}

func (debScanner) Scan(_ context.Context, _ Environment) ([]PackageRecord, []ScanError) {
	return scanDebianPackages()
}

func init() {
	Register(debScanner{})
}

// scanDebianPackages scans system-installed Python packages on Debian/Ubuntu
// by parsing /var/lib/dpkg/status directly — no binary invocation.
func scanDebianPackages() ([]PackageRecord, []ScanError) {
	pkgs, errs := scanDebianViaStatusFile()

	for i := range pkgs {
		pkgs[i].EnvType = EnvSystemDeb
		pkgs[i].Environment = "system"
		pkgs[i].InstallDate = ""
	}

	return pkgs, errs
}

// scanDebianViaStatusFile parses /var/lib/dpkg/status for Python packages.
//
// When SENTARI_SCAN_OS_PACKAGES=all is set, the isPythonPackage filter is
// lifted and every installed package is emitted so curated CPE entries
// for non-Python OS packages (openssl, libssl3, glibc, ...) can match on
// the server side.  Default ("python_only") preserves the historical
// Python-only behaviour.
func scanDebianViaStatusFile() ([]PackageRecord, []ScanError) {
	var packages []PackageRecord
	var scanErrs []ScanError

	statusFile := dpkgStatusPath
	// Bound the file first — a 1 TB malicious status file would
	// otherwise OOM the scanner during bufio streaming.  Size-cap
	// the size via os.Stat before opening for line-by-line read.
	// Use safeio.Open so a root-planted symlink at
	// /var/lib/dpkg/status (possible on a compromised host) is
	// refused rather than silently followed.
	if info, statErr := os.Lstat(statusFile); statErr == nil && info.Size() > maxDpkgStatusSize {
		scanErrs = append(scanErrs, ScanError{
			Path:      statusFile,
			EnvType:   EnvSystemDeb,
			Error:     "dpkg status file exceeds size cap",
			Timestamp: time.Now().UTC(),
		})
		return packages, scanErrs
	}
	file, err := safeio.Open(statusFile)
	if err != nil {
		scanErrs = append(scanErrs, ScanError{
			Path:      statusFile,
			EnvType:   EnvSystemDeb,
			Error:     err.Error(),
			Timestamp: time.Now().UTC(),
		})
		return packages, scanErrs
	}
	defer file.Close()

	mode := osScanMode()
	emitAll := mode == "all"

	var currentPkg PackageRecord
	// statusInstalled tracks the dpkg "Status:" want/flag/state triple for
	// the current stanza.  A removed-but-not-purged package carries e.g.
	// "deinstall ok config-files" and must NOT be reported as installed —
	// otherwise it produces persistent CVE false positives.  Defaults to
	// true so a stanza with no Status line at all is treated as installed.
	statusInstalled := true
	// seen de-duplicates byte-identical records.  On a multi-arch host
	// /var/lib/dpkg/status carries one stanza per architecture (e.g. libssl3
	// amd64 AND libssl3 i386, same Version) which would otherwise produce two
	// indistinguishable PackageRecords (there is no architecture field on the
	// v3 wire contract), doubling core-lib inventory counts in mode=all.  The
	// key is the full wire identity name+version+source: two stanzas sharing
	// it emit byte-identical records, so keeping one is lossless; genuinely
	// different versions of the same name differ in the key and are both kept.
	seen := make(map[string]struct{})
	emit := func(pkg PackageRecord) {
		key := pkg.Name + "\x00" + pkg.Version + "\x00" + pkg.SourcePackage
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		extractDebLicense(&pkg)
		packages = append(packages, pkg)
	}
	scanner := bufio.NewScanner(file)
	// dpkg writes single-line Depends:/Provides: fields on big metapackages
	// that are NOT RFC822-folded and can exceed bufio's default 64 KiB token
	// cap; Scan would then return bufio.ErrTooLong, ending the loop and
	// silently dropping every stanza after the oversized one.  The whole
	// status file is already size-capped at maxDpkgStatusSize upstream, so a
	// single line cannot exceed that — use it as the max token size so one
	// long field never truncates the remaining inventory.
	scanner.Buffer(make([]byte, 0, 64<<10), int(maxDpkgStatusSize))

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			if currentPkg.Name != "" && statusInstalled && (emitAll || isPythonPackage(currentPkg.Name)) {
				emit(currentPkg)
			}
			currentPkg = PackageRecord{}
			statusInstalled = true
			continue
		}

		if strings.HasPrefix(line, "Package: ") {
			currentPkg.Name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		} else if strings.HasPrefix(line, "Version: ") {
			currentPkg.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
		} else if strings.HasPrefix(line, "Status: ") {
			// dpkg "Status:" is a "<want> <flag> <state>" triple; the state
			// determines whether the package files are actually on disk.
			// States like "config-files" (removed, config kept) or
			// "not-installed" must be excluded from the reported inventory.
			status := strings.TrimSpace(strings.TrimPrefix(line, "Status: "))
			statusInstalled = isInstalledState(status)
		} else if strings.HasPrefix(line, "Source: ") {
			// dpkg "Source:" is "<name>" or "<name> (<version>)"; keep just
			// the source package name so the server can match a binary like
			// libssl3 against a source-keyed advisory (openssl).
			src := strings.TrimSpace(strings.TrimPrefix(line, "Source: "))
			if idx := strings.IndexByte(src, '('); idx >= 0 {
				src = strings.TrimSpace(src[:idx])
			}
			currentPkg.SourcePackage = src
		} else if strings.HasPrefix(line, "Maintainer:") {
			// dpkg "Maintainer:" is "Name <email>" — the NTIA supplier
			// element. NormalizeSupplier strips the email so maintainer PII
			// stays out of auditor-facing SBOMs (SBOM-completeness v2 Gap 1).
			currentPkg.Supplier = NormalizeSupplier(strings.TrimSpace(strings.TrimPrefix(line, "Maintainer:")))
		}
	}

	// Handle last entry (no trailing blank line).
	if currentPkg.Name != "" && statusInstalled && (emitAll || isPythonPackage(currentPkg.Name)) {
		emit(currentPkg)
	}

	if err := scanner.Err(); err != nil {
		scanErrs = append(scanErrs, ScanError{
			Path:      statusFile,
			EnvType:   EnvSystemDeb,
			Error:     err.Error(),
			Timestamp: time.Now().UTC(),
		})
	}

	return packages, scanErrs
}

// extractDebLicense reads the Debian copyright file for a package and
// populates license fields.  Sets tier to "unknown" when:
//   - the copyright file is missing
//   - the copyright file is a symlink (a malicious package can plant
//     “copyright -> /etc/shadow“ and our earlier implementation would
//     exfiltrate the target into the scan payload — now refused)
//   - the copyright file exceeds maxDebCopyrightSize
//   - the raw license text is empty
func extractDebLicense(pkg *PackageRecord) {
	copyrightPath := filepath.Join("/usr/share/doc", pkg.Name, "copyright")
	data, err := safeio.ReadFile(copyrightPath, maxDebCopyrightSize)
	if err != nil {
		// Any of missing/symlink/too-large → tier unknown.  Log via
		// stderr only for symlink and size-cap cases so operators can
		// audit suspicious packages on a compromised host.
		if stderrors.Is(err, safeio.ErrSymlink) || stderrors.Is(err, safeio.ErrTooLarge) {
			// Keep the stderr noise down for missing files (common);
			// only flag the refusal cases.
			_, _ = os.Stderr.WriteString(
				"WARNING: refused " + copyrightPath + " — " + err.Error() + "\n",
			)
		}
		pkg.LicenseTier = "unknown"
		return
	}
	rawLic := ExtractLicenseFromDebCopyright(string(data))
	if rawLic != "" {
		pkg.LicenseRaw = rawLic
		pkg.LicenseSPDX, pkg.LicenseTier = NormalizeLicense(rawLic)
	} else {
		pkg.LicenseTier = "unknown"
	}
}

// isInstalledState reports whether a dpkg "Status:" "<want> <flag> <state>"
// triple represents a package whose files are present on disk.
//
// "installed" is the steady state, but "triggers-awaited", "triggers-pending"
// and "unpacked" ALSO have their files on disk:
//   - for the two trigger states every file is unpacked and the package is
//     functional — dpkg is merely waiting to run a deferred trigger (ldconfig,
//     man-db, …);
//   - for "unpacked" all files have been extracted to disk and only the
//     postinst/config step is still pending.
//
// All three carry real, CVE-relevant files, so dropping them would hide
// otherwise-present packages whenever a scan races trigger processing or a
// partially-applied apt transaction.  The genuinely-incomplete or removed
// states ("config-files", "not-installed", "half-installed",
// "half-configured") stay excluded because their files are absent or only
// partially written.
func isInstalledState(status string) bool {
	fields := strings.Fields(status)
	if len(fields) == 0 {
		return false
	}
	switch fields[len(fields)-1] {
	case "installed", "triggers-awaited", "triggers-pending", "unpacked":
		return true
	default:
		return false
	}
}

// isPackageNameDelimiter reports whether r separates tokens in a dpkg/rpm
// package name.  Names are built from lowercase letters and digits joined by
// '-', '.', '+' and '_' (e.g. libpipewire-0.3-0, python3.11), so any rune that
// is not [a-z0-9] is a token boundary.
func isPackageNameDelimiter(r rune) bool {
	return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
}

// isPipToken reports whether a delimited name token is the pip tool: bare
// "pip" or pip with a numeric version suffix ("pip3").  Because '.' is a
// delimiter the token never carries a dotted suffix, so only trailing digits
// are possible.  Crucially this rejects "pipewire" (suffix "ewire"), which a
// raw strings.Contains(name, "pip") would wrongly accept.
func isPipToken(tok string) bool {
	rest, ok := strings.CutPrefix(tok, "pip")
	if !ok {
		return false
	}
	for _, r := range rest {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// isPythonPackage returns true if the OS package name denotes a Python
// interpreter, runtime, or Python library/tool package.
//
// Matching a raw substring is unsafe for "pip": it occurs inside the PipeWire
// audio stack — pipewire, pipewire-bin, pipewire-pulse, libpipewire-0.3-0,
// gstreamer1.0-pipewire (PipeWire is the default audio server since Ubuntu
// 22.10) — which the legacy predicate misreported as Python inventory in the
// default python_only mode.  This predicate is shared with the rpm scanner, so
// the same false positives leaked onto RHEL/Fedora/SUSE hosts.
//
// The fix matches on token/prefix boundaries instead:
//   - "python", "pypy" and "jython" stay substring matches — they are
//     distinctive enough that no realistic non-Python package contains them,
//     and this keeps catching libpython3.11, python3-<name>, gcc-python3, etc.;
//   - "pip" is accepted only as a whole delimited token (pip, pip3, or
//     python3-pip where "pip" is a standalone token), never as an arbitrary
//     substring — so the PipeWire family is no longer mistaken for Python.
func isPythonPackage(name string) bool {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "python") ||
		strings.Contains(lower, "pypy") ||
		strings.Contains(lower, "jython") {
		return true
	}
	for _, tok := range strings.FieldsFunc(lower, isPackageNameDelimiter) {
		if isPipToken(tok) {
			return true
		}
	}
	return false
}
