package scanner

import (
	"encoding/binary"
	"fmt"
)

// RPM header tag constants (from rpm/rpmtag.h).
const (
	rpmTagVersion   = 1001
	rpmTagRelease   = 1002
	rpmTagEpoch     = 1003
	rpmTagVendor    = 1011 // supplier (organization that built the package)
	rpmTagLicense   = 1014
	rpmTagPackager  = 1015 // supplier fallback (person/team that packaged it)
	rpmTagSourceRPM = 1044
	rpmTypeInt32    = 4 // RPM_INT32_TYPE
	rpmTypeString   = 6 // RPM_STRING_TYPE

	// rpmdb.sqlite header blob starts with nindex + hsize (no file magic).
	rpmBlobHeaderSize = 8  // 4 bytes nindex + 4 bytes hsize
	rpmEntrySize      = 16 // tag(4) + type(4) + offset(4) + count(4)
)

// parseRPMHeaderVersion parses a raw RPM header blob and returns
// "version-release" (e.g. "3.12.0-1"). Returns "" if parsing fails.
func parseRPMHeaderVersion(blob []byte) string {
	version, _, _, _ := parseRPMHeader(blob)
	return version
}

// sourceNameFromSourceRPM derives the source package name from a SOURCERPM
// value like "openssl-1.1.1k-7.el9.src.rpm" → "openssl". RPM SOURCERPM is
// "<name>-<version>-<release>.src.rpm"; the name may itself contain hyphens
// (openssl-libs), so we strip the ".src.rpm" / ".nosrc.rpm" suffix and drop
// the trailing two hyphen-delimited segments (version, release).
func sourceNameFromSourceRPM(srpm string) string {
	s := srpm
	for _, suffix := range []string{".src.rpm", ".nosrc.rpm", ".rpm"} {
		if len(s) > len(suffix) && s[len(s)-len(suffix):] == suffix {
			s = s[:len(s)-len(suffix)]
			break
		}
	}
	// Drop the last two "-" segments (release then version).
	for n := 0; n < 2; n++ {
		idx := -1
		for i := len(s) - 1; i >= 0; i-- {
			if s[i] == '-' {
				idx = i
				break
			}
		}
		if idx <= 0 {
			return ""
		}
		s = s[:idx]
	}
	return s
}

// parseRPMHeader parses a raw RPM header blob as stored in the rpmdb.sqlite
// Packages table and returns (version, license). The blob format is big-endian:
//
//	[0:4]  nindex  — number of index entries
//	[4:8]  hsize   — size of the data store in bytes
//	[8:]   nindex × 16-byte index entries (tag, type, offset, count)
//	       followed by the data store
//
// Returns (version, license, source, supplier); any element is "" when its
// tag is absent or parsing fails. Supplier prefers VENDOR (the building
// organization) and falls back to PACKAGER — both are raw here; the caller
// runs NormalizeSupplier before emission.
func parseRPMHeader(blob []byte) (string, string, string, string) {
	if len(blob) < rpmBlobHeaderSize {
		return "", "", "", ""
	}

	nindex := int(binary.BigEndian.Uint32(blob[0:4]))
	// hsize := binary.BigEndian.Uint32(blob[4:8]) — not needed directly

	// Sanity bound: RPM packages rarely have more than a few hundred header
	// tags.  Cap at 10 000 to prevent integer overflow on 32-bit platforms
	// (nindex * rpmEntrySize could wrap) and billion-iteration loops on 64-bit.
	if nindex <= 0 || nindex > 10000 {
		return "", "", "", ""
	}

	indexEnd := rpmBlobHeaderSize + nindex*rpmEntrySize
	if len(blob) < indexEnd {
		return "", "", "", ""
	}

	storeStart := indexEnd

	var version, release, license, sourceRPM, vendor, packager string
	var epoch uint32

	for i := 0; i < nindex; i++ {
		base := rpmBlobHeaderSize + i*rpmEntrySize
		tag := binary.BigEndian.Uint32(blob[base : base+4])
		typ := binary.BigEndian.Uint32(blob[base+4 : base+8])
		offset := int(binary.BigEndian.Uint32(blob[base+8 : base+12]))
		// count at base+12 not needed for STRING/INT32-scalar types

		// EPOCH is stored as a big-endian INT32 in the data store, not a
		// null-terminated string.  Read it explicitly so epoch-qualified
		// versions ("32:9.16.23-11.el9") match the server's EVR splitter
		// and epoch-scoped OSV advisories (e.g. bind on RHEL 9).
		if tag == rpmTagEpoch && typ == rpmTypeInt32 {
			if offset < 0 || storeStart+offset+4 > len(blob) {
				continue
			}
			epoch = binary.BigEndian.Uint32(blob[storeStart+offset : storeStart+offset+4])
			continue
		}

		if typ != rpmTypeString {
			continue
		}
		if tag != rpmTagVersion && tag != rpmTagRelease && tag != rpmTagLicense &&
			tag != rpmTagSourceRPM && tag != rpmTagVendor && tag != rpmTagPackager {
			continue
		}

		// Safe arithmetic: ensure offset is non-negative and storeStart+offset
		// does not overflow or exceed the blob length.
		if offset < 0 || offset > len(blob)-storeStart {
			continue
		}
		strStart := storeStart + offset
		if strStart >= len(blob) {
			continue
		}

		// Null-terminated string in the data store.
		strEnd := strStart
		for strEnd < len(blob) && blob[strEnd] != 0 {
			strEnd++
		}
		s := string(blob[strStart:strEnd])

		switch tag {
		case rpmTagVersion:
			version = s
		case rpmTagRelease:
			release = s
		case rpmTagLicense:
			license = s
		case rpmTagSourceRPM:
			sourceRPM = s
		case rpmTagVendor:
			vendor = s
		case rpmTagPackager:
			packager = s
		}
	}

	versionStr := ""
	if version != "" {
		versionStr = version
		if release != "" {
			versionStr = version + "-" + release
		}
		// Epoch-qualify the EVR when a nonzero epoch is present so the
		// value matches the server's "epoch:version-release" splitter.
		if epoch > 0 {
			versionStr = fmt.Sprintf("%d:%s", epoch, versionStr)
		}
	}

	// VENDOR is the organization that built the package (e.g. "Red Hat, Inc.",
	// "Fedora Project"); PACKAGER is the person/team. Prefer VENDOR as the more
	// stable supplier identity, fall back to PACKAGER.
	supplier := vendor
	if supplier == "" {
		supplier = packager
	}

	return versionStr, license, sourceNameFromSourceRPM(sourceRPM), supplier
}
