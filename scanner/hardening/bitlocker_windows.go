//go:build windows

package hardening

import (
	"bytes"
	"encoding/binary"

	"golang.org/x/sys/windows"
)

// winBitLocker reports disk_encryption.root_encrypted for Windows (partial
// tier). It performs a RAW read of \\.\PhysicalDrive0 and inspects each
// partition's volume boot record for the BitLocker "-FVE-FS-" signature. A
// BitLocker-protected volume carries that signature at byte offset 3 of its
// VBR; an unencrypted NTFS volume carries "NTFS    " there instead.
//
// Crucially we read the PHYSICAL DRIVE at the partition's byte offset, NOT the
// \\.\C: volume handle — a mounted, unlocked BitLocker volume presents the
// DECRYPTED view through the volume handle, so reading it would always show
// "NTFS" and produce a false "not encrypted". The physical-drive path sees the
// on-disk (encrypted) VBR with the FVE signature intact.
//
// Honesty: an absent signature OR any read failure yields `unknown` (null value
// + error), NEVER a false FAIL — we cannot prove a disk is unencrypted from a
// best-effort raw probe, and a false "not encrypted" on a compliant host is
// worse than an honest unknown.
func winBitLocker() []Observation {
	key := familyDiskEncryption + ".root_encrypted"
	const src = `\\.\PhysicalDrive0`

	encrypted, ok := physicalDriveHasFVE(src)
	if !ok {
		return []Observation{obsError(key, familyDiskEncryption, src, "raw drive unreadable (BitLocker state indeterminate)")}
	}
	if !encrypted {
		// No FVE signature found on any inspected partition. We do NOT emit a
		// false FAIL: absence is treated as indeterminate for this partial-tier
		// check.
		return []Observation{obsError(key, familyDiskEncryption, src, "no -FVE-FS- signature found (indeterminate)")}
	}
	return []Observation{obsValue(key, familyDiskEncryption, "true", src, "")}
}

// fveSignature is the BitLocker VBR magic at offset 3 of an encrypted volume.
var fveSignature = []byte("-FVE-FS-")

// physicalDriveHasFVE opens the raw physical drive, parses its (MBR or GPT)
// partition table, and checks each partition's first sector for the FVE
// signature. Returns (encrypted, ok); ok=false means the probe could not be
// completed (open/read failure).
func physicalDriveHasFVE(path string) (encrypted bool, ok bool) {
	h, err := openRawDevice(path)
	if err != nil {
		return false, false
	}
	defer windows.CloseHandle(h)

	sector0, err := readAt(h, 0, 512)
	if err != nil {
		return false, false
	}

	offsets := partitionOffsets(sector0, h)
	if len(offsets) == 0 {
		// Could not enumerate partitions; check sector 0 itself as a last
		// resort (a superfloppy / whole-disk volume).
		if hasFVEAt(sector0) {
			return true, true
		}
		return false, true
	}
	for _, off := range offsets {
		vbr, err := readAt(h, off, 512)
		if err != nil {
			continue
		}
		if hasFVEAt(vbr) {
			return true, true
		}
	}
	return false, true
}

// hasFVEAt reports whether a 512-byte VBR carries the FVE signature at offset 3.
func hasFVEAt(vbr []byte) bool {
	return len(vbr) >= 11 && bytes.Equal(vbr[3:11], fveSignature)
}

// partitionOffsets returns the byte offsets of partitions from an MBR or GPT.
func partitionOffsets(sector0 []byte, h windows.Handle) []uint64 {
	if len(sector0) < 512 {
		return nil
	}
	// GPT protective MBR: partition type 0xEE at the first MBR entry.
	if sector0[450] == 0xEE {
		return gptPartitionOffsets(h)
	}
	return mbrPartitionOffsets(sector0)
}

// mbrPartitionOffsets parses the classic 4-entry MBR partition table.
func mbrPartitionOffsets(sector0 []byte) []uint64 {
	const sectorSize = 512
	var out []uint64
	for i := 0; i < 4; i++ {
		e := 446 + i*16
		typ := sector0[e+4]
		if typ == 0x00 {
			continue
		}
		startLBA := binary.LittleEndian.Uint32(sector0[e+8 : e+12])
		if startLBA == 0 {
			continue
		}
		out = append(out, uint64(startLBA)*sectorSize)
	}
	return out
}

// gptPartitionOffsets parses the GPT header + entries to list partition byte
// offsets.
func gptPartitionOffsets(h windows.Handle) []uint64 {
	const sectorSize = 512
	hdr, err := readAt(h, sectorSize, sectorSize) // LBA 1
	if err != nil || len(hdr) < 92 || string(hdr[0:8]) != "EFI PART" {
		return nil
	}
	entriesLBA := binary.LittleEndian.Uint64(hdr[72:80])
	numEntries := binary.LittleEndian.Uint32(hdr[80:84])
	entrySize := binary.LittleEndian.Uint32(hdr[84:88])
	// entrySize is attacker-influenced (a corrupt/hostile GPT header). Cap it so
	// tableBytes = numEntries*entrySize cannot drive a ~1TB make([]byte, …).
	// The UEFI spec minimum is 128; real tables use 128, never near 4096.
	if entrySize < 128 || entrySize > 4096 || numEntries == 0 || numEntries > 256 {
		return nil
	}
	tableBytes := uint64(numEntries) * uint64(entrySize)
	table, err := readAt(h, entriesLBA*sectorSize, int(tableBytes))
	if err != nil {
		return nil
	}
	var out []uint64
	zeroType := make([]byte, 16)
	for i := uint32(0); i < numEntries; i++ {
		base := uint64(i) * uint64(entrySize)
		if base+128 > uint64(len(table)) {
			break
		}
		typeGUID := table[base : base+16]
		if bytes.Equal(typeGUID, zeroType) {
			continue // unused entry
		}
		firstLBA := binary.LittleEndian.Uint64(table[base+32 : base+40])
		out = append(out, firstLBA*sectorSize)
	}
	return out
}

// openRawDevice opens a device path for unbuffered raw reads.
func openRawDevice(path string) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(
		p,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		0,
		0,
	)
}

// readAt reads n bytes from the device handle at byte offset off. Raw device
// reads must be sector-aligned; all callers pass sector-aligned offsets and
// 512-byte (or table) lengths.
func readAt(h windows.Handle, off uint64, n int) ([]byte, error) {
	low := uint32(off & 0xFFFFFFFF)
	high := int32(off >> 32)
	if _, err := windows.SetFilePointer(h, int32(low), &high, windows.FILE_BEGIN); err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	var read uint32
	if err := windows.ReadFile(h, buf, &read, nil); err != nil {
		return nil, err
	}
	return buf[:read], nil
}
