package gobinaries

import (
	"debug/buildinfo"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/sentari-dev/sentari-agent/scanner"
	"github.com/sentari-dev/sentari-agent/scanner/safeio"
)

// maxGoBinaryBytes caps the on-disk size of a candidate before it is opened.
// debug/buildinfo reads are offset-bounded, so this is defence-in-depth, not a
// correctness requirement; it mirrors the JVM plugin's 512 MiB archive cap. A
// var so tests can lower it. Oversize candidates are surfaced as a ScanError
// (visible), not silently dropped.
var maxGoBinaryBytes int64 = 512 << 20

// acceptedMagics is the set of first-four-bytes (read big-endian) that mark an
// object-file container debug/buildinfo can parse: ELF, thin and fat Mach-O
// (both byte orders, 32- and 64-bit). PE ("MZ") is handled separately since it
// is a two-byte signature. A .class file shares the 0xCAFEBABE fat-Mach-O
// magic; it passes the sniff and then fails buildinfo.Read cleanly — harmless.
var acceptedMagics = map[uint32]struct{}{
	0x7f454c46: {}, // ELF "\x7fELF"
	0xFEEDFACE: {}, // Mach-O 32 MH_MAGIC
	0xFEEDFACF: {}, // Mach-O 64 MH_MAGIC_64
	0xCEFAEDFE: {}, // Mach-O 32 MH_CIGAM
	0xCFFAEDFE: {}, // Mach-O 64 MH_CIGAM_64
	0xCAFEBABE: {}, // Mach-O fat FAT_MAGIC
	0xCAFEBABF: {}, // Mach-O fat FAT_MAGIC_64
	0xBEBAFECA: {}, // Mach-O fat FAT_CIGAM
	0xBFBAFECA: {}, // Mach-O fat FAT_CIGAM_64
}

// looksLikeObjectFile reports whether the first bytes match a container format
// debug/buildinfo can read. It filters out scripts, text, and archives before
// any parse work.
func looksLikeObjectFile(head []byte) bool {
	if len(head) < 4 {
		return false
	}
	if head[0] == 'M' && head[1] == 'Z' { // PE / MS-DOS stub
		return true
	}
	m := binary.BigEndian.Uint32(head[:4])
	_, ok := acceptedMagics[m]
	return ok
}

// probeBinary inspects one filesystem path and returns the module records it
// carries, if any. It never executes the file: candidates are Lstat-gated
// (symlinks and irregular files refused), size-capped, magic-sniffed, and only
// then read with debug/buildinfo through the symlink-refusing safeio.Open.
// Non-Go files fail the parse and are skipped silently; only I/O and cap
// conditions produce a ScanError.
//
// probeBinary is a pure, platform-independent probe over any candidate path:
// the Windows ".exe" name gate lives at the walk (scanBinDir), not here, so the
// probe/format logic can be exercised cross-platform against ELF/PE/Mach-O
// fixtures on any host.
func probeBinary(path string) ([]scanner.PackageRecord, []scanner.ScanError) {
	// Lstat gate: skip symlinks (size-cap-bypass vector) and non-regular
	// files (FIFO/device — hang/unbounded-read vectors) before opening.
	li, err := os.Lstat(path)
	if err != nil {
		return nil, []scanner.ScanError{stampless(path, fmt.Sprintf("lstat: %v", err))}
	}
	if mode := li.Mode(); mode&os.ModeSymlink != 0 || !mode.IsRegular() {
		return nil, nil
	}
	if li.Size() > maxGoBinaryBytes {
		return nil, []scanner.ScanError{stampless(path,
			fmt.Sprintf("binary exceeds size cap: %d > %d bytes; skipped", li.Size(), maxGoBinaryBytes))}
	}

	// safeio.Open refuses a symlink at the leaf and re-verifies regular-file
	// on the held fd (no path-based TOCTOU); *os.File satisfies io.ReaderAt.
	f, err := safeio.Open(path)
	if err != nil {
		if os.IsPermission(err) {
			return nil, []scanner.ScanError{stampless(path, fmt.Sprintf("open: %v", err))}
		}
		// A file that turned non-regular between Lstat and open is a skip,
		// not a diagnostic.
		return nil, nil
	}
	defer f.Close()

	head := make([]byte, 4)
	if _, err := f.ReadAt(head, 0); err != nil {
		// Too small to be an object file, or an I/O error on a tiny read.
		return nil, nil
	}
	if !looksLikeObjectFile(head) {
		return nil, nil
	}

	bi, err := buildinfo.Read(f)
	if err != nil {
		// "not a Go executable" / malformed container — the normal case for
		// a non-Go binary sitting in an install directory. Skip silently.
		return nil, nil
	}
	records, errs := recordsFromBuildInfo(bi, path)
	// SHA-256 of the binary FILE belongs on the MAIN-module record only (the
	// binary *is* the main module). Dependency and stdlib records are embedded
	// coordinates with no separate file, so they get no hash — a wrong hash is
	// worse than none (SBOM-completeness v2 §4.5). Hashing is capped by the same
	// maxGoBinaryBytes gate already applied to the file above.
	if bi.Main.Path != "" {
		if sum := scanner.HashArtifact(path, maxGoBinaryBytes); sum != "" {
			for i := range records {
				if records[i].Name == bi.Main.Path {
					records[i].Sha256 = sum
					break
				}
			}
		}
	}
	return records, errs
}

// stampless builds a ScanError with a zero timestamp; the caller stamps it at
// the package boundary (the JVM convention keeps the extractor time-independent).
func stampless(path, msg string) scanner.ScanError {
	return scanner.ScanError{Path: path, EnvType: EnvGoBinary, Error: msg}
}
