package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// Fuzz targets for the metadata parsers.
//
// Each parser is reachable from scan data the agent ingests off the
// local filesystem, so any crash, hang, or panic is a one-way ticket
// into the scan cycle — a single malformed METADATA in a shared
// site-packages could freeze the daemon for every host on a fleet.
//
// Run for 5 minutes in CI (`go test -fuzz=. -fuzztime=5m ./scanner/`)
// and an hour nightly; corpus additions live under testdata/fuzz/.

// FuzzNormalizeLicense exercises the SPDX / tier mapper against
// arbitrary byte strings.  Must never panic — it's called once per
// package on every scan, so a crash here takes the scan down.
func FuzzNormalizeLicense(f *testing.F) {
	f.Add("MIT")
	f.Add("Apache-2.0")
	f.Add("")
	f.Add("GPL-3.0-or-later")
	f.Add("\x00\x01\x02")
	f.Add("LicenseRef-Custom-\u2603")
	f.Add(string(make([]byte, 1<<16))) // 64 KiB of nulls

	f.Fuzz(func(t *testing.T, raw string) {
		// We don't assert return values — any non-panic outcome is
		// acceptable — but the function must terminate and not
		// mutate global state.
		spdx, tier := NormalizeLicense(raw)
		_ = spdx
		_ = tier
	})
}

// FuzzExtractLicenseFromMetadata exercises the RFC 822-style parser
// used for pip METADATA and PKG-INFO.  Attacker-controlled bytes
// reach this via site-packages/*.dist-info/METADATA.
func FuzzExtractLicenseFromMetadata(f *testing.F) {
	f.Add("License: MIT\n")
	f.Add("")
	f.Add("Classifier: License :: OSI Approved :: Apache Software License\n")
	f.Add("License: \nClassifier: License :: OSI Approved :: BSD\n")
	f.Add("License:\n\n\n\n\n")
	// Null bytes inside a header shouldn't break the parser.
	f.Add("License: MIT\x00GPL-3.0\n")

	f.Fuzz(func(t *testing.T, content string) {
		raw, spdx, tier := ExtractLicenseFromMetadata(content)
		_ = raw
		_ = spdx
		_ = tier
	})
}

// FuzzExtractLicenseFromDebCopyright exercises the Debian copyright
// parser — the same one that reads the symlink-exfil target in a
// compromised /usr/share/doc/*/copyright.  Even with safeio refusing
// the symlink, the parser still has to handle arbitrary attacker
// bytes in a legitimately-installed-but-malicious package.
func FuzzExtractLicenseFromDebCopyright(f *testing.F) {
	f.Add("License: GPL-2+\nOther: stuff\n")
	f.Add("")
	f.Add("License:\n")
	f.Add("\n\n\nLicense: MIT\n")

	f.Fuzz(func(t *testing.T, content string) {
		got := ExtractLicenseFromDebCopyright(content)
		_ = got
	})
}

// FuzzExtractLicenseFromCondaJSON exercises the conda metadata JSON
// license extractor.  Input may or may not be valid JSON — the
// function must tolerate either.
func FuzzExtractLicenseFromCondaJSON(f *testing.F) {
	f.Add([]byte(`{"license":"MIT","name":"foo","version":"1"}`))
	f.Add([]byte(``))
	f.Add([]byte(`{`))
	f.Add([]byte(`null`))
	// Over-nested JSON to stress the decoder.
	deep := []byte("{" + string(make([]byte, 4096)) + "}")
	f.Add(deep)

	f.Fuzz(func(t *testing.T, data []byte) {
		raw, spdx, tier := ExtractLicenseFromCondaJSON(data)
		_ = raw
		_ = spdx
		_ = tier
	})
}

// FuzzParseCondaPackageMetadata reaches the full file-reading path.
// We write the fuzz input to a temp file and invoke the parser the
// same way the scanner does.  Catches crashes in the json.Unmarshal
// path and any downstream field access that assumes well-formed
// metadata.
func FuzzParseCondaPackageMetadata(f *testing.F) {
	f.Add([]byte(`{"name":"foo","version":"1.0"}`))
	f.Add([]byte(``))
	f.Add([]byte(`invalid`))

	f.Fuzz(func(t *testing.T, data []byte) {
		tmp := t.TempDir()
		path := filepath.Join(tmp, "fuzz.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Skip(err)
		}
		_, _ = parseCondaPackageMetadata(path, tmp)
	})
}

// FuzzParseRPMHeader exercises the hand-rolled RPM header parser in
// rpm_header.go.  The parser reads attacker-controlled blobs out of
// the rpmdb SQLite file; any crash here takes the entire scan down
// even though the RPM database itself isn't symlink-exfil-able (it
// lives under /var/lib/rpm which is root-owned).
func FuzzParseRPMHeader(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("not an rpm header"))
	// Minimal-but-invalid 16-byte blob.
	f.Add(make([]byte, 16))
	// Valid magic + garbage.
	f.Add(append([]byte{0x8e, 0xad, 0xe8, 0x01}, make([]byte, 128)...))

	f.Fuzz(func(t *testing.T, blob []byte) {
		version, license := parseRPMHeader(blob)
		_ = version
		_ = license
	})
}
