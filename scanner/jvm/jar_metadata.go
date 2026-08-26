// Package jvm extracts package identity metadata from JAR / WAR / EAR /
// JMOD files without invoking any Java toolchain (ADR 0003: zero binary
// execution).  Identity comes from on-disk artefacts in the following
// precedence:
//
//  1. `META-INF/maven/<groupId>/<artifactId>/pom.properties` — the
//     canonical Maven coordinate.  A shaded uber-jar carries one of
//     these per embedded library; we emit one PackageRecord per file.
//  2. `META-INF/MANIFEST.MF` — OSGi `Bundle-SymbolicName` +
//     `Bundle-Version` when present (OSGi is authoritative for its
//     own bundles); else `Implementation-Title` + `Implementation-
//     Version` as a generic last fallback.
//  3. **Filename** — `<artifact>-<version>.jar` parsing.  Heuristic,
//     but the only option for JARs that ship neither Maven metadata
//     nor OSGi headers (e.g. older Apache Commons releases).
//
// Size caps exist on every parse to defend against malicious or
// corrupt archives — see the max* constants.  The zip format's own
// path-normalisation means entries like `../../etc/passwd` never
// escape the archive's virtual namespace; the parser still only reads
// specific logical paths, so a zip-slip entry is either picked up
// unambiguously as its stated name or ignored.
package jvm

import (
	"archive/zip"
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"

	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
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
	// maxNestedDepth bounds the recursion into Spring Boot / Quarkus
	// / shaded uber-jars.  Real-world uber-jars nest 1 level (Spring
	// Boot BOOT-INF/lib/*.jar).  A shaded uber-jar that itself
	// contains another uber-jar is 2.  Beyond 3 is almost certainly
	// an attacker-crafted zip bomb designed to exhaust the scanner;
	// we refuse and emit a ScanError rather than recurse indefinitely.
	maxNestedDepth = 3
	// maxNestedJarBytes is the per-nested-member read cap.  If a
	// nested JAR entry decompresses to more than this, we stop
	// reading and surface a ScanError.  Deliberately much smaller
	// than the 512 MiB outer-file cap: real nested library jars are
	// under ~50 MiB, and the outer cap applied per-level across the
	// depth-3 recursion (512 MiB × 3 × workers) would let a crafted
	// bomb pin gigabytes of RAM per worker.  64 MiB comfortably fits
	// every legitimate nested jar we have seen.
	maxNestedJarBytes = 64 * 1024 * 1024
)

// maxNestedInFlightBytes caps the *cumulative* decompressed bytes a
// single outer JAR may materialise across its entire nested-jar
// subtree.  maxNestedJarBytes bounds one member; this bounds the sum,
// so a wide fan-out of many just-under-cap members (or a deflate bomb
// whose on-disk size hides its expanded size) can't exhaust memory.
// When the budget is spent the remaining subtree is skipped with a
// ScanError, mirroring the depth-cap behaviour.
//
// A var, not a const, so tests can lower it to exercise the budget
// path without having to materialise 256 MiB of fixtures.
var maxNestedInFlightBytes int64 = 256 * 1024 * 1024

// maxRecordsPerJAR caps the total number of PackageRecords a single
// outer JAR may emit across its *entire* extraction — the identity
// records of the outer archive, every pom.properties inside it, and
// every record produced by descending into nested jars all draw from
// this one shared budget.  Without a single shared cap a crafted JAR
// could bypass the limit by mixing paths: e.g. a central directory
// listing millions of tiny META-INF/maven/<g>/<a>/pom.properties
// entries would otherwise build an unbounded pomEntries slice and emit
// an unbounded number of records, amplifying a small on-disk archive
// into gigabytes of resident memory.  The budget is threaded by
// reference through the recursion so pom records and nested-jar records
// cannot each individually stay under the cap while together blowing
// past it.  When the budget is spent the remainder is skipped with a
// single ScanError, mirroring the depth-cap / byte-budget behaviour.
//
// A var, not a const, so tests can lower it to exercise the cap path
// without having to materialise 10 000 fixture entries.
var maxRecordsPerJAR = 10_000

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
// the "continuation line" convention: any line starting with a single
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
//	spring-boot-2.7.18-RELEASE.jar → spring-boot + 2.7.18-RELEASE
//	lib-1.0-SNAPSHOT.jar           → lib         + 1.0-SNAPSHOT
//	tools.jar                      → tools       + ""
//	nothing-like-a-version.jar     → nothing-like-a-version + ""
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

// extractFromJar is the top-level entrypoint.  Given a path to a JAR
// on disk, it opens the zip and delegates to extractFromReader, which
// is also the recursion point for nested-jar traversal (Spring Boot /
// Quarkus uber-jars — see nested_jar.go).
//
// Invariants:
//   - Never panics — corrupt zips, missing metadata, oversized members
//     all surface as ScanError entries.
//   - Never emits more than maxRecordsPerJAR records per outer JAR.
//   - Recursion depth bounded by maxNestedDepth.
func extractFromJar(jarPath string) ([]scanner.PackageRecord, []scanner.ScanError) {
	// Open through safeio (O_NOFOLLOW|O_NONBLOCK + fstat regular check)
	// rather than zip.OpenReader: the latter follows a `*.jar` symlink
	// and blocks forever on a FIFO named `*.jar`.  safeio refuses both
	// promptly.  We then hand the fd to zip.NewReader (which needs the
	// archive size, taken from the same fd's stat to avoid a TOCTOU).
	f, err := safeio.Open(jarPath)
	if err != nil {
		return nil, []scanner.ScanError{{
			Path:    jarPath,
			EnvType: EnvJVM,
			Error:   fmt.Sprintf("open zip: %v", err),
		}}
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, []scanner.ScanError{{
			Path:    jarPath,
			EnvType: EnvJVM,
			Error:   fmt.Sprintf("stat zip: %v", err),
		}}
	}
	zr, err := zip.NewReader(f, info.Size())
	if err != nil {
		return nil, []scanner.ScanError{{
			Path:    jarPath,
			EnvType: EnvJVM,
			Error:   fmt.Sprintf("open zip: %v", err),
		}}
	}
	budget := maxNestedInFlightBytes
	// remaining is the shared per-outer-JAR record budget.  It is passed
	// by reference into the recursion so pom records + nested-jar records
	// together respect maxRecordsPerJAR (see the const's doc comment).
	remaining := maxRecordsPerJAR
	records, errs := extractFromReader(zr, jarPath, 0, &budget, &remaining)
	// A jar that yields EXACTLY ONE coordinate is a plain library jar: the file
	// hashes cleanly to that single coordinate (SBOM-completeness v2 §4.5). An
	// uber/shaded jar (or one bundling nested jars) yields multiple embedded
	// coordinates whose artifact hash is NOT the outer file's — those are left
	// unhashed rather than stamped with a wrong hash.
	if len(records) == 1 {
		if sum := scanner.HashArtifact(jarPath, maxJARBytes); sum != "" {
			records[0].Sha256 = sum
		}
	}
	return records, errs
}

// extractFromReader is the recursion core.  Given an already-opened
// `*zip.Reader` and a `displayPath` naming this archive (for
// outer JARs: the filesystem path; for nested: `outer!/inner.jar`),
// it applies the precedence rules for identity, then descends into
// any nested .jar entries found.
//
// `depth` starts at 0 for the physical outer JAR; increases by 1
// per recursion.  When depth reaches maxNestedDepth, this function
// still extracts identity but refuses to recurse further and emits a
// ScanError naming the depth-4 child that was skipped.
// `budget` points at the remaining cumulative in-flight byte allowance
// for the *outer* JAR (see maxNestedInFlightBytes).  It is shared by
// reference across the whole recursion so a wide-and-deep bomb draws
// from one shared pool; when it is exhausted the remaining nested
// members are skipped with a ScanError.
// `remaining` points at the shared per-outer-JAR record budget (see
// maxRecordsPerJAR).  It, too, is shared by reference so pom records and
// nested-jar records draw from one pool and cannot collectively exceed
// the cap.
func extractFromReader(r *zip.Reader, displayPath string, depth int, budget *int64, remaining *int) ([]scanner.PackageRecord, []scanner.ScanError) {
	// Single pass over entries to classify them.  This is cheaper than
	// three separate passes and keeps the O(n) bound explicit.
	var (
		pomEntries    []*zip.File
		manifestEntry *zip.File
		nestedJARs    []*zip.File
	)
	// pomTruncated records that we stopped collecting pom.properties
	// entries because the shared record budget was already saturated —
	// so extractIdentity can surface a single "record cap exceeded"
	// ScanError.  Bounding the *slice* (not just the emit) is what keeps
	// a JAR whose central directory lists millions of pom.properties
	// entries from amplifying a tiny on-disk archive into an unbounded
	// resident slice.
	pomTruncated := false
	for _, f := range r.File {
		name := path.Clean(f.Name)
		// Zip-slip guard: refuse entries that try to walk out of the
		// archive's virtual root (`../etc/passwd` etc).  The
		// extractor doesn't extract-to-disk, but a malicious entry
		// name could otherwise mislead the metadata pickers.
		if strings.HasPrefix(name, "..") {
			continue
		}
		// Directory entries carry zero data — skip.
		if strings.HasSuffix(f.Name, "/") {
			continue
		}
		switch {
		case strings.HasPrefix(f.Name, "META-INF/maven/") &&
			strings.HasSuffix(f.Name, "/pom.properties"):
			// Never retain more pom entries than the shared record budget
			// could ever emit: extractIdentity emits at most one record
			// per entry, and the whole subtree may emit at most *remaining
			// more records.  Anything beyond that is guaranteed to be
			// skipped, so we refuse to even hold a reference to it.
			if len(pomEntries) >= *remaining {
				pomTruncated = true
				continue
			}
			pomEntries = append(pomEntries, f)
		case f.Name == "META-INF/MANIFEST.MF":
			manifestEntry = f
		case isJARLike(f.Name):
			// Same rationale as pom entries: a nested jar yields at least
			// one record (filename fallback), so we never need to retain
			// more than *remaining candidates.  Anything beyond that is
			// dropped here and reported by the descent loop's cap check.
			if len(nestedJARs) >= *remaining {
				continue
			}
			nestedJARs = append(nestedJARs, f)
		}
	}

	records, errs := extractIdentity(displayPath, pomEntries, manifestEntry, remaining, pomTruncated)

	// Descend into nested JARs.  Every .jar / .war / .ear / .jmod
	// inside this archive is its own artefact with its own coordinates
	// — Spring Boot / Quarkus / shaded uber-jars all end up here.
	// Agnostic to framework: we descend based on filename suffix, not
	// on Spring Boot's `BOOT-INF/lib/` path, so new uber-jar
	// conventions Just Work.
	for _, f := range nestedJARs {
		if *remaining <= 0 {
			errs = append(errs, scanner.ScanError{
				Path:    displayPath,
				EnvType: EnvJVM,
				Error:   fmt.Sprintf("record cap exceeded (%d); remaining nested jars skipped", maxRecordsPerJAR),
			})
			break
		}
		childPath := displayPath + "!/" + f.Name
		if depth+1 > maxNestedDepth {
			errs = append(errs, scanner.ScanError{
				Path:    childPath,
				EnvType: EnvJVM,
				Error:   fmt.Sprintf("nested JAR depth cap exceeded (max %d); subtree skipped", maxNestedDepth),
			})
			continue
		}

		// Cumulative byte-budget guard.  Refuse to materialise this
		// member if the outer JAR has already spent its allowance, or
		// if the member's declared uncompressed size alone would blow
		// it.  The declared size is a cheap pre-check; the actual bytes
		// read (bounded by maxNestedJarBytes) are debited below, so a
		// member that lies about its size still can't overrun the pool
		// by more than one capped read.
		if *budget <= 0 || f.UncompressedSize64 > uint64(*budget) {
			errs = append(errs, scanner.ScanError{
				Path:    childPath,
				EnvType: EnvJVM,
				Error:   fmt.Sprintf("nested JAR byte budget exceeded (max %d bytes); subtree skipped", maxNestedInFlightBytes),
			})
			continue
		}

		body, readErr := readZipMember(f, maxNestedJarBytes)
		if readErr != nil {
			errs = append(errs, scanner.ScanError{
				Path:    childPath,
				EnvType: EnvJVM,
				Error:   fmt.Sprintf("read nested jar: %v", readErr),
			})
			continue
		}
		// Debit the shared pool by the bytes we actually pulled into
		// memory (not the declared size), so liars are charged their
		// real cost.
		*budget -= int64(len(body))
		childReader, zerr := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if zerr != nil {
			errs = append(errs, scanner.ScanError{
				Path:    childPath,
				EnvType: EnvJVM,
				Error:   fmt.Sprintf("parse nested jar: %v", zerr),
			})
			continue
		}
		childRecs, childErrs := extractFromReader(childReader, childPath, depth+1, budget, remaining)
		records = append(records, childRecs...)
		errs = append(errs, childErrs...)
	}

	return records, errs
}

// extractIdentity runs the Precedence 1-3 rules on the three entry
// sets classified by the caller.  Returns the identity records for
// the archive *itself* — nested-jar records are a separate concern
// handled by the recursion.
func extractIdentity(displayPath string, pomEntries []*zip.File, manifestEntry *zip.File, remaining *int, pomTruncated bool) ([]scanner.PackageRecord, []scanner.ScanError) {
	var records []scanner.PackageRecord
	var errs []scanner.ScanError

	// capped is set if we ran out of the shared record budget while
	// emitting pom records, or if classification already dropped pom
	// entries because the budget was saturated.  Either way we surface
	// exactly one ScanError, mirroring the depth-cap / byte-budget style.
	capped := pomTruncated

	// Precedence 1 — pom.properties (can produce multiple records for
	// a shaded uber-jar).
	for _, f := range pomEntries {
		if *remaining <= 0 {
			// Shared record budget exhausted mid-JAR: stop emitting and
			// flag the truncation for a single aggregated ScanError.
			capped = true
			break
		}
		body, err := readZipMember(f, maxPomPropertiesBytes)
		if err != nil {
			errs = append(errs, scanner.ScanError{
				Path:    displayPath + "!/" + f.Name,
				EnvType: EnvJVM,
				Error:   fmt.Sprintf("read pom.properties: %v", err),
			})
			continue
		}
		pp, err := parsePomProperties(body)
		if err != nil {
			errs = append(errs, scanner.ScanError{
				Path:    displayPath + "!/" + f.Name,
				EnvType: EnvJVM,
				Error:   err.Error(),
			})
			continue
		}
		// A pom.properties with missing groupId OR artifactId is
		// unusable as an identity; skip it and let the caller fall
		// through.  Missing version is still a useful record for
		// wildcard CVE advisories.
		if pp.GroupID == "" || pp.ArtifactID == "" {
			continue
		}
		records = append(records, scanner.PackageRecord{
			Name:        pp.GroupID + ":" + pp.ArtifactID,
			Version:     pp.Version,
			InstallPath: displayPath,
			EnvType:     EnvJVM,
			Environment: displayPath,
		})
		*remaining--
	}
	if capped {
		errs = append(errs, scanner.ScanError{
			Path:    displayPath,
			EnvType: EnvJVM,
			Error:   fmt.Sprintf("record cap exceeded (%d); remaining pom.properties skipped", maxRecordsPerJAR),
		})
	}
	if len(records) > 0 {
		return records, errs
	}

	// Precedence 2 — MANIFEST.MF.  Only reached when no pom record was
	// emitted, which (given the pom loop decrements *remaining on every
	// emit and returns above once len(records)>0) guarantees the shared
	// budget still has room here; the fallback record is charged below.
	if manifestEntry != nil {
		body, err := readZipMember(manifestEntry, maxManifestBytes)
		if err != nil {
			errs = append(errs, scanner.ScanError{
				Path:    displayPath + "!/META-INF/MANIFEST.MF",
				EnvType: EnvJVM,
				Error:   fmt.Sprintf("read manifest: %v", err),
			})
		} else {
			mi, perr := parseManifest(body)
			if perr != nil {
				errs = append(errs, scanner.ScanError{
					Path:    displayPath + "!/META-INF/MANIFEST.MF",
					EnvType: EnvJVM,
					Error:   perr.Error(),
				})
			} else if rec, ok := manifestToRecord(displayPath, mi); ok {
				records = append(records, rec)
				*remaining--
			}
		}
	}
	if len(records) > 0 {
		return records, errs
	}

	// Precedence 3 — filename fallback.  Parses the trailing filename
	// component; for nested paths like `outer!/BOOT-INF/lib/x.jar` we
	// want the inner filename only, so split on the last `/`.
	filename := displayPath
	if idx := strings.LastIndex(filename, "/"); idx >= 0 {
		filename = filename[idx+1:]
	}
	artifact, version := parseFilename(filename)
	records = append(records, scanner.PackageRecord{
		Name:        artifact,
		Version:     version,
		InstallPath: displayPath,
		EnvType:     EnvJVM,
		Environment: displayPath,
	})
	*remaining--
	return records, errs
}

// isJARLike returns true if the given archive entry path looks like a
// Java archive we should try to descend into.  Deliberately agnostic
// of Spring Boot / Quarkus / shaded conventions — any archive-named
// entry is a candidate.  Framework-specific path checks would break
// as soon as the next uber-jar layout appears.
func isJARLike(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range []string{".jar", ".war", ".ear", ".jmod"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
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

// readZipMember reads at most `max+1` bytes from a zip member.  The
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
