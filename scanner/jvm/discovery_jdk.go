package jvm

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// jdkWellKnownRoots is the per-OS list of directories where JDKs are
// customarily installed system-wide.  The discoverer walks one level
// deep under each root and accepts any child whose shape passes
// ``looksLikeJDK``.  Exposed as a package-level variable (not a const)
// so tests can redirect it at a fixture tree.
//
// The lists below deliberately err on the side of "include a few extra
// paths" — the cost of a non-existent directory is a single stat call,
// while a missed path means a customer's JDK goes unscanned and
// therefore unscanned-for-CVEs.
var jdkWellKnownRoots = initJDKRoots()

func initJDKRoots() []string {
	switch runtime.GOOS {
	case "linux":
		return []string{
			"/usr/lib/jvm",
			"/usr/java",
			"/opt/java",
			"/opt/jdk",
		}
	case "darwin":
		return []string{
			"/Library/Java/JavaVirtualMachines",
			"/System/Library/Java/JavaVirtualMachines",
		}
	case "windows":
		return []string{
			`C:\Program Files\Java`,
			`C:\Program Files\Eclipse Adoptium`,
			`C:\Program Files\Zulu`,
			`C:\Program Files\Microsoft`, // Microsoft JDK installs here
			`C:\Program Files (x86)\Java`,
		}
	default:
		return nil
	}
}

// discoverJDK returns Environments for each JDK install reachable on
// this host.  Identifies a JDK by presence of a ``release`` file or
// ``lib/modules`` (the JPMS module image); both are produced by every
// JDK since 9 and by no other kind of directory.
//
// Precedence + deduplication:
//
//   1. $JAVA_HOME if set and shaped like a JDK.
//   2. Per-OS well-known install directories, walked one level deep
//      (we accept ``/usr/lib/jvm/temurin-21`` but not
//      ``/usr/lib/jvm/temurin-21/lib``).
//
// A JDK that appears in both lists is emitted exactly once — the
// path equality check in ``containsPath`` catches $JAVA_HOME
// pointing at /usr/lib/jvm/<name>.
func discoverJDK() []scanner.Environment {
	var out []scanner.Environment

	if jh := os.Getenv("JAVA_HOME"); jh != "" {
		jh = filepath.Clean(jh)
		if looksLikeJDK(jh) {
			out = append(out, scanner.Environment{
				EnvType: EnvJVM,
				Name:    layoutJDKRuntime,
				Path:    jh,
			})
		}
	}

	for _, root := range jdkWellKnownRoots {
		entries, err := os.ReadDir(root)
		if err != nil {
			// Directory missing / unreadable — not an error for us;
			// there just isn't a JDK here.
			continue
		}
		for _, d := range entries {
			if !d.IsDir() {
				continue
			}
			candidate := filepath.Join(root, d.Name())
			// On macOS, ``/Library/Java/JavaVirtualMachines/<name>.jdk``
			// is a bundle directory; the actual JDK home (with the
			// ``release`` file and ``lib/modules``) is nested under
			// ``Contents/Home``.  Resolve that first so looksLikeJDK
			// sees the real layout.  On Linux/Windows the flat layout
			// is the norm and this branch is a no-op.
			if runtime.GOOS == "darwin" {
				if inner := filepath.Join(candidate, "Contents", "Home"); looksLikeJDK(inner) {
					candidate = inner
				}
			}
			if !looksLikeJDK(candidate) {
				continue
			}
			if containsPath(out, candidate) {
				continue
			}
			out = append(out, scanner.Environment{
				EnvType: EnvJVM,
				Name:    layoutJDKRuntime,
				Path:    candidate,
			})
		}
	}

	return out
}

// looksLikeJDK returns true iff the given directory contains either
// a ``release`` file (OpenJDK / Oracle / Adoptium / Zulu / GraalVM
// convention) or ``lib/modules`` (the JPMS module image, present in
// every JDK ≥ 9).  Using two signals rather than one avoids
// false-negatives on exotic minimal JDKs that strip the release
// file for size.
func looksLikeJDK(root string) bool {
	if _, err := os.Stat(filepath.Join(root, "release")); err == nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(root, "lib", "modules")); err == nil {
		return true
	}
	return false
}

// scanJDKRuntime walks a JDK install, delegating to the shared
// scanDirTree for per-JAR extraction, and then post-processes the
// results so ``.jmod`` records carry the JDK's own version (read
// from the ``release`` file) when the filename fallback left
// Version empty.  Without this, ``java.base.jmod`` would be reported
// as (java.base, "") and CVE correlation would have nothing to
// match against.
func scanJDKRuntime(root string) ([]scanner.PackageRecord, []scanner.ScanError) {
	jdkVersion := readJDKVersion(root)
	records, errs := scanDirTree(root)
	if jdkVersion == "" {
		return records, errs
	}
	for i := range records {
		if !strings.HasSuffix(strings.ToLower(records[i].InstallPath), ".jmod") {
			continue
		}
		if records[i].Version == "" {
			records[i].Version = jdkVersion
		}
	}
	return records, errs
}

// readJDKVersion parses the JDK ``release`` file (key=value format,
// values optionally quoted) and returns the JAVA_VERSION.  Returns
// "" if the file is missing, unreadable, or lacks the key.
//
// The release-file format is ad-hoc but stable across JDK vendors:
//
//   JAVA_VERSION="21.0.3"
//   IMPLEMENTOR="Eclipse Adoptium"
//
// Some builds (notably older GraalVM and some Azul CI images) omit
// the quotes; the parser tolerates both.
func readJDKVersion(root string) string {
	path := filepath.Join(root, "release")
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		// Match the key exactly: without this, JAVA_VERSION_DATE (a
		// real key on modern release files) matches HasPrefix and we
		// return the date instead of the version.
		key := strings.TrimSpace(line[:idx])
		if key != "JAVA_VERSION" {
			continue
		}
		val := strings.TrimSpace(line[idx+1:])
		val = strings.Trim(val, `"`)
		return val
	}
	// Surface scanner errors explicitly (oversized lines, read errors).
	// We still return "" — the JDK version is a nice-to-have, not a
	// hard requirement — but ignoring Err() silently hides real bugs.
	if err := sc.Err(); err != nil {
		return ""
	}
	return ""
}
