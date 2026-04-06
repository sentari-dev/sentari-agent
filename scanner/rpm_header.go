package scanner

import "encoding/binary"

// RPM header tag constants (from rpm/rpmtag.h).
const (
	rpmTagVersion = 1001
	rpmTagRelease = 1002
	rpmTypeString = 6 // RPM_STRING_TYPE

	// rpmdb.sqlite header blob starts with nindex + hsize (no file magic).
	rpmBlobHeaderSize = 8  // 4 bytes nindex + 4 bytes hsize
	rpmEntrySize      = 16 // tag(4) + type(4) + offset(4) + count(4)
)

// parseRPMHeaderVersion parses a raw RPM header blob as stored in the
// rpmdb.sqlite Packages table and returns "version-release" (e.g. "3.12.0-1").
// The blob format is big-endian:
//
//	[0:4]  nindex  — number of index entries
//	[4:8]  hsize   — size of the data store in bytes
//	[8:]   nindex × 16-byte index entries (tag, type, offset, count)
//	       followed by the data store
//
// Returns an empty string if parsing fails or the version tag is absent.
func parseRPMHeaderVersion(blob []byte) string {
	if len(blob) < rpmBlobHeaderSize {
		return ""
	}

	nindex := int(binary.BigEndian.Uint32(blob[0:4]))
	// hsize := binary.BigEndian.Uint32(blob[4:8]) — not needed directly

	// Sanity bound: RPM packages rarely have more than a few hundred header
	// tags.  Cap at 10 000 to prevent integer overflow on 32-bit platforms
	// (nindex * rpmEntrySize could wrap) and billion-iteration loops on 64-bit.
	if nindex <= 0 || nindex > 10000 {
		return ""
	}

	indexEnd := rpmBlobHeaderSize + nindex*rpmEntrySize
	if len(blob) < indexEnd {
		return ""
	}

	storeStart := indexEnd

	var version, release string

	for i := 0; i < nindex; i++ {
		base := rpmBlobHeaderSize + i*rpmEntrySize
		tag := binary.BigEndian.Uint32(blob[base : base+4])
		typ := binary.BigEndian.Uint32(blob[base+4 : base+8])
		offset := int(binary.BigEndian.Uint32(blob[base+8 : base+12]))
		// count at base+12 not needed for STRING type

		if typ != rpmTypeString {
			continue
		}
		if tag != rpmTagVersion && tag != rpmTagRelease {
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
		}
	}

	if version == "" {
		return ""
	}
	if release != "" {
		return version + "-" + release
	}
	return version
}
