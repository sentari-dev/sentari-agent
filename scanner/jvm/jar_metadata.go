// Package jvm extracts package identity metadata from JAR / WAR / EAR /
// JMOD files without invoking any Java toolchain (ADR 0003: zero binary
// execution).  Identity comes from on-disk artefacts in the following
// precedence:
//
//  1. ``META-INF/maven/<groupId>/<artifactId>/pom.properties`` — the
//     canonical Maven coordinate.  A shaded uber-jar carries one of
//     these per embedded library; we emit one PackageRecord per file.
//  2. ``META-INF/MANIFEST.MF`` — OSGi ``Bundle-SymbolicName`` +
//     ``Bundle-Version`` when present (OSGi is authoritative for its
//     own bundles); else ``Implementation-Title`` + ``Implementation-
//     Version`` as a generic last fallback.
//  3. **Filename** — ``<artifact>-<version>.jar`` parsing.  Heuristic,
//     but the only option for JARs that ship neither Maven metadata
//     nor OSGi headers (e.g. older Apache Commons releases).
//
// Size caps exist on every parse to defend against malicious or
// corrupt archives — see the max* constants.  ZIP entry names are
// treated as raw names; safety here does NOT come from the ZIP
// format normalising them.  This parser only reads specific
// logical member paths (``META-INF/maven/*/pom.properties``,
// ``META-INF/MANIFEST.MF``) after explicit traversal-check
// validation, so entries such as ``../../etc/passwd`` are rejected
// before they can be used as metadata sources.
package jvm

import (
	"archive/zip"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner"
)

// EnvType value this package emits on every PackageRecord.  Keep it
// equal to scanner.EnvJVM once the registry entry lands (Phase C);
// for now the JVM plugin's own env-type constant is defined here so
// the extractor + its tests are self-contained.
const EnvJVM = "jvm"

// Size caps.  These are deliberately generous for legitimate use but
// tight enough that a malicious archive can't OOM the scanner.  Real
// pom.properties files are a few hundred bytes; real MANIFEST.MFs are
// a few KiB.  Real JARs (not uber-jars) are typically under 10 MiB
// but Spring Boot uber-jars exceed 100 MiB routinely — 512 MiB is the
// top end we still process; beyond that we skip + emit a ScanError.
const (
	maxPomPropertiesBytes = 64 * 1024
	maxManifestBytes      = 1 * 1024 * 1024
	maxJARBytes           = 512 * 1024 * 1024
	maxRecordsPerJAR      = 10_000
)

// PomProperties is the parsed shape of a META-INF/maven .pom.properties
// file.  All three identity fields are populated on a well-formed file;
// a partial parse (missing any of groupId / artifactId / version) is
// returned with empty strings in the missing slots so the caller can
// decide whether to use the partial data or fall through.
type PomProperties struct {
	GroupID    string
	ArtifactID string
	Version    string
}

// ManifestInfo is the parsed shape of a META-INF/MANIFEST.MF file.
// OSGi headers and Implementation-* headers often coexist — the caller
// picks whichever is non-empty first based on the context (OSGi for
// OSGi bundles, Implementation-* as a generic fallback).
type ManifestInfo struct {
	BundleSymbolicName    string
	BundleVersion         string
	ImplementationTitle   string
	ImplementationVersion string
	SpecificationTitle    string
	SpecificationVersion  string
	BundleLicense         string
}

// parsePomProperties reads a pom.properties body as bytes and returns
// the extracted coordinates.  Malformed lines (no '=') are skipped;
// the first '=' is the separator, so values may themselves contain
// '='.  Any file exceeding maxPomPropertiesBytes is rejected.
func parsePomProperties(data []byte) (PomProperties, error) {
	if len(data) > maxPomPropertiesBytes {
		return PomProperties{}, fmt.Errorf(
			"pom.properties exceeds size cap: %d > %d bytes",
			len(data), maxPomPropertiesBytes,
		)
	}
	var out PomProperties
	sc := bufio.NewScanner(bytes.NewReader(data))
	// A pom.properties line can be fairly long if authors jam metadata
	// into the version; allow up to the whole cap as a single line.
	sc.Buffer(make([]byte, 0, 4096), maxPomPropertiesBytes+1)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		switch key {
		case "groupId":
			out.GroupID = val
		case "artifactId":
			out.ArtifactID = val
		case "version":
			out.Version = val
		}
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("pom.properties scan: %w", err)
	}
	return out, nil
}

// parseManifest reads a MANIFEST.MF body.  Supports both CRLF (per
// spec) and LF-only (common enough in the wild to tolerate).  Handles
// the ``continuation line'' convention: any line starting with a single
// space is appended to the value of the previous header.
func parseManifest(data []byte) (ManifestInfo, error) {
	if len(data) > maxManifestBytes {
		return ManifestInfo{}, fmt.Errorf(
			"MANIFEST.MF exceeds size cap: %d > %d bytes",
			len(data), maxManifestBytes,
		)
	}
	// Normalise line endings to LF so the walker below is simpler.
	// This allocates once; manifests are small enough not to matter.
	normalised := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))

	type kv struct{ key, val string }
	var headers []kv
	cur := kv{}
	emit := func() {
		if cur.key != "" {
			headers = append(headers, cur)
			cur = kv{}
		}
	}

	for _, raw := range bytes.Split(normalised, []byte("\n")) {
		line := string(raw)
		if line == "" {
			emit()
			continue
		}
		if line[0] == ' ' {
			// Continuation.  Per spec, exactly one leading space is
			// stripped and the rest is appended to the previous value.
			cur.val += line[1:]
			continue
		}
		// Start of a new header.  Flush the pending one first.
		emit()
		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			// Not a header line; ignore (not an error — real manifests
			// have occasional blank + signed-jar sections we don't
			// care about).
			continue
		}
		cur.key = strings.TrimSpace(line[:idx])
		cur.val = strings.TrimSpace(line[idx+1:])
	}
	emit()

	var out ManifestInfo
	for _, h := range headers {
		switch h.key {
		case "Bundle-SymbolicName":
			// Strip any OSGi directives after ';' — "com.foo;singleton:=true"
			if semi := strings.IndexByte(h.val, ';'); semi >= 0 {
				out.BundleSymbolicName = strings.TrimSpace(h.val[:semi])
			} else {
				out.BundleSymbolicName = h.val
			}
		case "Bundle-Version":
			out.BundleVersion = h.val
		case "Bundle-License":
			out.BundleLicense = h.val
		case "Implementation-Title":
			out.ImplementationTitle = h.val
		case "Implementation-Version":
			out.ImplementationVersion = h.val
		case "Specification-Title":
			out.SpecificationTitle = h.val
		case "Specification-Version":
			out.SpecificationVersion = h.val
		}
	}
	return out, nil
}

// parseFilename is the last-resort identity extractor.  It splits a
// filename like "commons-lang3-3.12.0.jar" into ("commons-lang3",
// "3.12.0") using the Maven convention: the version suffix begins at
// the last hyphen whose next character is a digit.  This handles:
//
//   spring-boot-2.7.18-RELEASE.jar → spring-boot + 2.7.18-RELEASE
//   lib-1.0-SNAPSHOT.jar           → lib         + 1.0-SNAPSHOT
//   tools.jar                      → tools       + ""
//   nothing-like-a-version.jar     → nothing-like-a-version + ""
//
// Returns ("", "") if the input doesn't look like a JAR at all.
func parseFilename(name string) (artifact, version string) {
	base := filepath.Base(name)
	lower := strings.ToLower(base)
	ext := ""
	for _, e := range []string{".jar", ".war", ".ear", ".jmod"} {
		if strings.HasSuffix(lower, e) {
			ext = e
			break
		}
	}
	if ext == "" {
		return "", ""
	}
	stem := base[:len(base)-len(ext)]

	// Walk hyphens right-to-left; the first one whose successor is a
	// digit is the version split.
	for i := len(stem) - 1; i >= 0; i-- {
		if stem[i] != '-' {
			continue
		}
		if i+1 < len(stem) && stem[i+1] >= '0' && stem[i+1] <= '9' {
			return stem[:i], stem[i+1:]
		}
	}
	// No digit-prefixed suffix — return the stem as the artefact with
	// an empty version.
	return stem, ""
}

// extractFromJar is the top-level entrypoint.  Given a path to a JAR,
// it opens the zip, tries each metadata source in precedence order,
// and returns the resulting PackageRecord(s) plus any non-fatal scan
// errors encountered along the way.
//
// Invariants:
//   - Never panics — corrupt zips, missing metadata, oversized members
//     all surface as ScanError entries.
//   - Never emits more than maxRecordsPerJAR records.
//   - Never reads more than maxJARBytes from the underlying file.
func extractFromJar(jarPath string) ([]scanner.PackageRecord, []scanner.ScanError) {
	// Pre-open size check.  ``zip.OpenReader`` will parse the central
	// directory regardless of the file's total size, so an attacker-
	// supplied 10 GB "JAR" would still cause a lot of work before we
	// find out it's too big.  Stat first; reject at the boundary.
	if info, err := os.Stat(jarPath); err == nil && info.Size() > int64(maxJARBytes) {
		return nil, []scanner.ScanError{{
			Path:    jarPath,
			EnvType: EnvJVM,
			Error: fmt.Sprintf(
				"JAR exceeds size cap before open: %d > %d bytes",
				info.Size(), maxJARBytes,
			),
		}}
	}

	rc, err := zip.OpenReader(jarPath)
	if err != nil {
		return nil, []scanner.ScanError{{
			Path:    jarPath,
			EnvType: EnvJVM,
			Error:   fmt.Sprintf("open zip: %v", err),
		}}
	}
	defer rc.Close()

	// Collect any pom.properties files first; if we find any, they win.
	var pomEntries []*zip.File
	var manifestEntry *zip.File
	for _, f := range rc.File {
		// Use the cleaned + validated path for EVERY decision below,
		// not f.Name.  An attacker-crafted entry named e.g.
		// ``META-INF/maven/../../etc/passwd/pom.properties`` would
		// pass the old HasPrefix/HasSuffix on the raw name but
		// escape the intended directory structure.  Cleaning and
		// then validating prefixes avoids that.
		name := path.Clean(f.Name)
		// Zip-slip + absolute-path guard.  An entry whose cleaned
		// name is "..", starts with "../", or is absolute
		// (``/etc/...``) is rejected before we ever read its bytes.
		if name == ".." || strings.HasPrefix(name, "../") || path.IsAbs(name) {
			continue
		}
		if strings.HasPrefix(name, "META-INF/maven/") &&
			strings.HasSuffix(name, "/pom.properties") {
			pomEntries = append(pomEntries, f)
		}
		if name == "META-INF/MANIFEST.MF" {
			manifestEntry = f
		}
	}

	var records []scanner.PackageRecord
	var errs []scanner.ScanError

	// Precedence 1 — pom.properties.
	for _, f := range pomEntries {
		if len(records) >= maxRecordsPerJAR {
			errs = append(errs, scanner.ScanError{
				Path:    jarPath,
				EnvType: EnvJVM,
				Error:   fmt.Sprintf("record cap exceeded (%d); remaining entries skipped", maxRecordsPerJAR),
			})
			break
		}
		body, err := readZipMember(f, maxPomPropertiesBytes)
		if err != nil {
			errs = append(errs, scanner.ScanError{
				Path:    jarPath + "!/" + f.Name,
				EnvType: EnvJVM,
				Error:   fmt.Sprintf("read pom.properties: %v", err),
			})
			continue
		}
		pp, err := parsePomProperties(body)
		if err != nil {
			errs = append(errs, scanner.ScanError{
				Path:    jarPath + "!/" + f.Name,
				EnvType: EnvJVM,
				Error:   err.Error(),
			})
			continue
		}
		// A pom.properties with missing groupId OR artifactId is
		// unusable as an identity; skip it and let the caller
		// potentially fall through to MANIFEST.MF.  Missing version
		// is kept because it's still a useful record for the CVE
		// layer to match against wildcard advisories.
		if pp.GroupID == "" || pp.ArtifactID == "" {
			continue
		}
		records = append(records, scanner.PackageRecord{
			Name:        pp.GroupID + ":" + pp.ArtifactID,
			Version:     pp.Version,
			InstallPath: jarPath,
			EnvType:     EnvJVM,
			Environment: jarPath,
		})
	}
	if len(records) > 0 {
		return records, errs
	}

	// Precedence 2 — MANIFEST.MF.
	if manifestEntry != nil {
		body, err := readZipMember(manifestEntry, maxManifestBytes)
		if err != nil {
			errs = append(errs, scanner.ScanError{
				Path:    jarPath + "!/META-INF/MANIFEST.MF",
				EnvType: EnvJVM,
				Error:   fmt.Sprintf("read manifest: %v", err),
			})
		} else {
			mi, perr := parseManifest(body)
			if perr != nil {
				errs = append(errs, scanner.ScanError{
					Path:    jarPath + "!/META-INF/MANIFEST.MF",
					EnvType: EnvJVM,
					Error:   perr.Error(),
				})
			} else if rec, ok := manifestToRecord(jarPath, mi); ok {
				records = append(records, rec)
			}
		}
	}
	if len(records) > 0 {
		return records, errs
	}

	// Precedence 3 — filename fallback.  Always yields at least an
	// empty-name record on a .jar input; the caller decides whether
	// empty-name records are worth uploading (they currently are —
	// missing JVM packages in the inventory is worse than having a
	// row whose Name is less authoritative).
	artifact, version := parseFilename(jarPath)
	records = append(records, scanner.PackageRecord{
		Name:        artifact,
		Version:     version,
		InstallPath: jarPath,
		EnvType:     EnvJVM,
		Environment: jarPath,
	})
	return records, errs
}

// manifestToRecord turns a parsed ManifestInfo into a PackageRecord.
// OSGi wins when present; Implementation-* is the generic fallback;
// Specification-* is a last resort rarely seen outside the JDK itself.
// Returns ok=false if none of the identity fields is populated.
func manifestToRecord(jarPath string, mi ManifestInfo) (scanner.PackageRecord, bool) {
	var name, version string
	switch {
	case mi.BundleSymbolicName != "":
		name = mi.BundleSymbolicName
		version = mi.BundleVersion
	case mi.ImplementationTitle != "":
		name = mi.ImplementationTitle
		version = mi.ImplementationVersion
	case mi.SpecificationTitle != "":
		name = mi.SpecificationTitle
		version = mi.SpecificationVersion
	default:
		return scanner.PackageRecord{}, false
	}
	rec := scanner.PackageRecord{
		Name:        name,
		Version:     version,
		InstallPath: jarPath,
		EnvType:     EnvJVM,
		Environment: jarPath,
		LicenseRaw:  mi.BundleLicense,
	}
	return rec, true
}

// readZipMember reads at most ``max+1`` bytes from a zip member.  The
// +1 is deliberate: it lets the caller detect "exceeded cap" vs "at
// cap exactly" without an extra stat call.  Returns an error if the
// archive's stream is bad.
func readZipMember(f *zip.File, max int) ([]byte, error) {
	rdr, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("open member: %w", err)
	}
	defer rdr.Close()
	lr := &io.LimitedReader{R: rdr, N: int64(max) + 1}
	body, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("read member: %w", err)
	}
	if int64(len(body)) > int64(max) {
		return nil, errors.New("member exceeds size cap")
	}
	return body, nil
}
