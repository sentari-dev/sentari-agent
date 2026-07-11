package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// Fuzz target for the dpkg /var/lib/dpkg/status field parser.
//
// scanDebianViaStatusFile streams /var/lib/dpkg/status line-by-line to build
// the Debian/Ubuntu system-package inventory. On a compromised or simply
// corrupt host that file is attacker-influenceable, so any panic, hang, or
// unbounded allocation in the stanza/field parsing is a direct hit on the scan
// cycle — a single malformed status file could freeze the daemon for every
// host on a fleet.
//
// The parser reads the path from the package-level dpkgStatusPath seam (the
// same seam the unit tests use via setDpkgStatusPath), so the fuzzer points it
// at a TempDir-resident status file holding the mutated bytes. The only
// invariant asserted is that the call terminates without panicking; the fuzz
// harness reports any panic as a failure. Return values are intentionally not
// asserted — any non-panic outcome (records, scan errors, or nothing) is
// acceptable for arbitrary input.
//
// Run in CI: go test -run=^$ -fuzz=FuzzScanDebianViaStatusFile -fuzztime=15s ./scanner/

// FuzzScanDebianViaStatusFile drives the dpkg status field parser with
// arbitrary status-file bytes written to a temp file behind the dpkgStatusPath
// seam.
func FuzzScanDebianViaStatusFile(f *testing.F) {
	// Seed 1: canonical multi-stanza status file (installed Python + OS pkgs).
	f.Add(`Package: python3
Version: 3.11.4-1
Status: install ok installed

Package: openssl
Version: 3.0.11-1ubuntu2
Status: install ok installed
Source: openssl (3.0.11-1ubuntu2)

Package: libssl3
Version: 3.0.11-1ubuntu2
Status: install ok installed
Source: openssl
`)
	// Seed 2: removed-but-not-purged stanza (config-files state) + no Status.
	f.Add("Package: ghost\nVersion: 1.0\nStatus: deinstall ok config-files\n\nPackage: no-status\nVersion: 2.0\n")
	// Seed 3: multi-arch duplicate stanzas (dedup path) + folded-ish fields.
	f.Add("Package: libc6\nVersion: 2.35\nStatus: install ok installed\nDepends: a, b, c\n\nPackage: libc6\nVersion: 2.35\nStatus: install ok installed\n")
	// Seed 4: structurally-degenerate / empty inputs.
	f.Add("")
	f.Add("Package:")
	f.Add("Package: x\nStatus:\nVersion:\nSource: (\n")
	// Seed 5: control bytes and a stray colon-less line.
	f.Add("\x00\x01\x02\nPackage: \x00\nVersion: \xff\nStatus: install ok installed\nnot-a-field-line\n")

	f.Fuzz(func(t *testing.T, statusRaw string) {
		dir := t.TempDir()
		fixture := filepath.Join(dir, "status")
		if err := os.WriteFile(fixture, []byte(statusRaw), 0o600); err != nil {
			t.Skip(err)
		}
		orig := dpkgStatusPath
		dpkgStatusPath = fixture
		defer func() { dpkgStatusPath = orig }()

		// The only contract on arbitrary input is: no panic, and the call
		// terminates. Return values are not asserted.
		pkgs, errs := scanDebianViaStatusFile()
		_ = pkgs
		_ = errs
	})
}
