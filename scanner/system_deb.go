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
	if _, err := os.Stat("/var/lib/dpkg/status"); err != nil {
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
func scanDebianViaStatusFile() ([]PackageRecord, []ScanError) {
	var packages []PackageRecord
	var errors []ScanError

	statusFile := "/var/lib/dpkg/status"
	// Bound the file first — a 1 TB malicious status file would
	// otherwise OOM the scanner during bufio streaming.  Size-cap
	// the size via os.Stat before opening for line-by-line read.
	// Use safeio.Open so a root-planted symlink at
	// /var/lib/dpkg/status (possible on a compromised host) is
	// refused rather than silently followed.
	if info, statErr := os.Lstat(statusFile); statErr == nil && info.Size() > maxDpkgStatusSize {
		errors = append(errors, ScanError{
			Path:      statusFile,
			EnvType:   EnvSystemDeb,
			Error:     "dpkg status file exceeds size cap",
			Timestamp: time.Now().UTC(),
		})
		return packages, errors
	}
	file, err := safeio.Open(statusFile)
	if err != nil {
		errors = append(errors, ScanError{
			Path:      statusFile,
			EnvType:   EnvSystemDeb,
			Error:     err.Error(),
			Timestamp: time.Now().UTC(),
		})
		return packages, errors
	}
	defer file.Close()

	var currentPkg PackageRecord
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()

		if line == "" {
			if currentPkg.Name != "" && isPythonPackage(currentPkg.Name) {
				extractDebLicense(&currentPkg)
				packages = append(packages, currentPkg)
			}
			currentPkg = PackageRecord{}
			continue
		}

		if strings.HasPrefix(line, "Package: ") {
			currentPkg.Name = strings.TrimSpace(strings.TrimPrefix(line, "Package: "))
		} else if strings.HasPrefix(line, "Version: ") {
			currentPkg.Version = strings.TrimSpace(strings.TrimPrefix(line, "Version: "))
		}
	}

	// Handle last entry (no trailing blank line).
	if currentPkg.Name != "" && isPythonPackage(currentPkg.Name) {
		extractDebLicense(&currentPkg)
		packages = append(packages, currentPkg)
	}

	if err := scanner.Err(); err != nil {
		errors = append(errors, ScanError{
			Path:      statusFile,
			EnvType:   EnvSystemDeb,
			Error:     err.Error(),
			Timestamp: time.Now().UTC(),
		})
	}

	return packages, errors
}

// extractDebLicense reads the Debian copyright file for a package and
// populates license fields.  Sets tier to "unknown" when:
//   - the copyright file is missing
//   - the copyright file is a symlink (a malicious package can plant
//     ``copyright -> /etc/shadow`` and our earlier implementation would
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

// isPythonPackage returns true if the package name is Python-related.
func isPythonPackage(name string) bool {
	lower := strings.ToLower(name)
	for _, pattern := range []string{"python", "pip", "pypy", "jython"} {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}
